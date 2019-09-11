/*
 * Authors:
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/compiler.h>
#include <linux/rbtree.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <net/netlink.h>
#include <net/sch_generic.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

struct tc_hdrr_opt {
    __u32 weight;
};
struct tc_hdrr_glob {
    __u64 rate;   // limited rate of the link
    __u32 defcls; // default class number
    __u32 direct_qlen; // Length of direct queue, in packets
};
struct tc_hdrr_xstats {
    __u32 deactivate_count;
    __u32 mark_idle_count;
};
enum {
	TCA_HDRR_UNSPEC,
	TCA_HDRR_PARMS,
	TCA_HDRR_INIT,
	__TCA_HDRR_MAX,
};
#define TCA_HDRR_MAX (__TCA_HDRR_MAX - 1)

/* HDRR algorithm
*/

/* interior & leaf nodes; props specific to leaves are marked L:
 * To reduce false sharing, place mostly read fields at beginning,
 * and mostly written ones at the end.
 */
struct hdrr_class {
	struct Qdisc_class_common common;

	struct tcf_proto __rcu  *filter_list;	/* class attached filters */
	struct tcf_block        *block;
	int                     filter_cnt;

	struct hdrr_class	*parent;

	struct gnet_stats_basic_packed  basic_stats;
    struct tc_hdrr_xstats           xstats;

    int children_count;
    int weight, quota;

    int drop_count;

	union {
		struct {
            struct Qdisc	*q;

            struct hdrr_class *next_leaf;

            bool is_active;
		} leaf;
		struct {
            int active_weight; // sum of weight of active & busy children
            int fairshare; // smallest value of `fairshare` to trigger distribution

            int current_round;
		} inner;
	};
};

struct hdrr_sched {
	struct Qdisc_class_hash clhash;
	int	                    default_class;		/* class where unclassified flows go to */

	/* filters for qdisc itself */
	struct tcf_proto __rcu  *filter_list;
	struct tcf_block        *block;

	struct qdisc_watchdog   watchdog;
    struct psched_ratecfg   rate;
    s64                     next_available;

	int direct_qlen;

	/* non shaped skbs; let them go directly thru */
	struct qdisc_skb_head   direct_queue;
	long                    direct_pkts;

    // Current state of the scheduler
    int current_round;
    struct hdrr_class *active_leaf;
    struct hdrr_class *first_leaf;
    struct hdrr_class *root;
};

void* const ll_tail = (void*)0x1;

static inline bool is_leaf(struct hdrr_class *cl) { return cl->children_count == 0; }

static inline bool is_active_leaf(struct hdrr_class *cl) { return cl->leaf.is_active; }
static inline bool is_active_inner(struct hdrr_class *cl) { return cl->inner.active_weight != 0; }

static inline bool is_attached_leaf(struct hdrr_class *cl) { return cl->leaf.next_leaf != NULL; }

static inline unsigned int classid(struct hdrr_class *cl) { return cl->common.classid & 0xffff; }

static inline int take_quota(struct hdrr_class *cl) {
    struct hdrr_class *parent = cl->parent;
    const int amount = parent->inner.fairshare * cl->weight;

    parent->quota -= amount;
    cl->quota += amount;

    return amount;
}

static inline void attach_leaf(struct hdrr_class *cl, struct hdrr_sched *q) {
    if (!is_attached_leaf(cl)) {
        cl->leaf.next_leaf = q->first_leaf;
        q->first_leaf = cl;
    }
}

static inline struct hdrr_class* get_leaf_at(struct hdrr_class **cl_ptr) {
    struct hdrr_class *cl = NULL;

    while((cl = *cl_ptr) != ll_tail && !is_active_leaf(cl)) {
        *cl_ptr = cl->leaf.next_leaf;
        cl->leaf.next_leaf = NULL;
    }
    return cl;
}

static inline void activate_leaf(struct hdrr_class *cl) {
    struct hdrr_class* ancestor;
    int weight = cl->weight;

    cl->leaf.is_active = true;

    for (ancestor = cl->parent; ancestor != NULL && ancestor->inner.active_weight == 0; ancestor = ancestor->parent) {
        // Inactive ancestor
        ancestor->inner.active_weight = weight;
        weight = ancestor->weight;
    }

    if (ancestor != NULL) {
        // First active ancestor
        ancestor->inner.active_weight += weight;
    }
}

static inline void deactivate_leaf(struct hdrr_class *cl) {
    struct hdrr_class* ancestor;
    int weight = cl->weight;
    int quota = cl->quota;

    cl->leaf.is_active = false;
    cl->quota = 0;
    cl->xstats.mark_idle_count += 1;

    for (ancestor = cl->parent; ancestor != NULL && ancestor->inner.active_weight == weight; ancestor = ancestor->parent) {
        // Ancestor with only `cl` as active leaf, deactivate it
        quota += ancestor->quota;
        ancestor->quota = 0;

        weight = ancestor->weight;
        ancestor->inner.active_weight = 0;
        ancestor->inner.fairshare = 0;
    }
    if (ancestor != NULL) {
        // Ancestor that remains active
        ancestor->inner.active_weight -= weight;
        ancestor->quota += quota;
    }
}

static void enter_leaf(struct hdrr_class* ancestor, int round) {
    if (ancestor->inner.current_round == round) {
        return;
    }
    ancestor->inner.current_round = round;

    if (ancestor->parent != NULL) {
        enter_leaf(ancestor->parent, round);
        take_quota(ancestor);
    }

    ancestor->inner.fairshare = max(ancestor->quota, 0) / ancestor->inner.active_weight;
}

static inline struct hdrr_class* advance_leaf(struct hdrr_sched* q, struct hdrr_class* cl) {
    int max_loop = 20;
    struct hdrr_class* next;

    if (unlikely(cl->parent == NULL)) {
        // Single-class hierarchy
        cl->quota = 0x7fffffff;
        return cl;
    }

    next = cl;
    do {
        next = get_leaf_at(&next->leaf.next_leaf);
        if (next == ll_tail) {
            next = get_leaf_at(&q->first_leaf);
            q->current_round += 1;
        }

        enter_leaf(next->parent, q->current_round);
        q->root->quota += take_quota(next);
    } while (next->quota < 0 && (max_loop--) >= 0);

    return next;
}

static inline void hdrr_internal_to_leaf(struct hdrr_sched *q, struct hdrr_class *cl,
			       struct Qdisc *new_q) {
    WARN_ON(is_active_inner(cl));

    memset(&cl->leaf, 0, sizeof(cl->leaf));

    cl->leaf.q = new_q ? new_q : &noop_qdisc;
}

static inline void hdrr_leaf_to_internal(struct hdrr_class *cl) {
    unsigned int qlen = cl->leaf.q->q.qlen;
    unsigned int backlog = cl->leaf.q->qstats.backlog;

    WARN_ON(is_active_leaf(cl));

    qdisc_reset(cl->leaf.q);
    qdisc_tree_reduce_backlog(cl->leaf.q, qlen, backlog);
    qdisc_destroy(cl->leaf.q);

    memset(&cl->inner, 0, sizeof(cl->inner));
}

static inline struct hdrr_class *hdrr_find(u32 handle, struct Qdisc *sch) {
	struct hdrr_sched *q = qdisc_priv(sch);
	struct Qdisc_class_common *clc;

	clc = qdisc_class_find(&q->clhash, handle);
	if (clc == NULL)
		return NULL;

	return container_of(clc, struct hdrr_class, common);
}

static unsigned long hdrr_search(struct Qdisc *sch, u32 handle) {
	return (unsigned long)hdrr_find(handle, sch);
}

static struct hdrr_class *hdrr_classify(struct sk_buff *skb, struct Qdisc *sch, int *qerr) {
	struct hdrr_sched *q = qdisc_priv(sch);
	struct hdrr_class *cl;
	struct tcf_result res;
	struct tcf_proto *tcf;
	int result;

	cl = hdrr_find(skb->priority, sch);
	if (cl) {
		if (is_leaf(cl))
			return cl;
		// Start with inner filter chain if a non-leaf class is selected 
		tcf = rcu_dereference_bh(cl->filter_list);
	} else {
		tcf = rcu_dereference_bh(q->filter_list);
	}

	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	while (tcf && (result = tcf_classify(skb, tcf, &res, false)) >= 0) {
		cl = (void *)res.class;
		if (!cl) {
			cl = hdrr_find(res.classid, sch);
			if (!cl)
				break;	// filter selected invalid classid
		}
		if (is_leaf(cl))
			return cl; // we hit leaf; return it

		// we have got inner class; apply inner filter chain
		tcf = rcu_dereference_bh(cl->filter_list);
	}
	// classification failed; try to use default class
    return hdrr_find(TC_H_MAKE(TC_H_MAJ(sch->handle), q->default_class), sch);
}

static void enqueue_tail(struct sk_buff *skb, struct Qdisc *sch, struct qdisc_skb_head *qh) {
	struct sk_buff *last = qh->tail;

	if (last) {
		skb->next = NULL;
		last->next = skb;
	} else {
		qh->head = skb;
	}
    qh->tail = skb;
	qh->qlen++;
}

static int hdrr_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free) {
    int uninitialized_var(ret);
    struct hdrr_sched *q = qdisc_priv(sch);
    struct hdrr_class *cl = hdrr_classify(skb, sch, &ret);

    if (!cl) {
        // No class found, push it to direct class
        // TODO: Should this be default behaviour?
        if (q->direct_queue.qlen < q->direct_qlen) {
            enqueue_tail(skb, sch, &q->direct_queue);
            q->direct_pkts++;
            goto succeed;
        } else {
            //printk("Dropping");
            return qdisc_drop(skb, sch, to_free);
        }
    }

    if ((ret = qdisc_enqueue(skb, cl->leaf.q, to_free)) != NET_XMIT_SUCCESS) {
        //printk("Dropping %d", classid(cl));
        if (net_xmit_drop_count(ret)) {
            qdisc_qstats_drop(sch);
            cl->drop_count++;
        }
        return ret;
    }

    if (!is_active_leaf(cl)) {
        attach_leaf(cl, q);
        activate_leaf(cl);
        if (q->active_leaf == NULL) {
            q->active_leaf = cl;
        }
    }

succeed:
    qdisc_qstats_backlog_inc(sch, skb);
    sch->q.qlen++;
    return NET_XMIT_SUCCESS;
}

static struct sk_buff *hdrr_dequeue(struct Qdisc *sch) {
    struct hdrr_sched *q = qdisc_priv(sch);
    struct hdrr_class *cl = q->active_leaf;

    struct sk_buff *skb = NULL;
    bool is_direct = false;

    int max_loop;
    s64 now = 0;
    
	skb = __qdisc_dequeue_head(&q->direct_queue);
	if (skb != NULL || !sch->q.qlen || !cl) {
        is_direct = true;
		goto end;
    }

    if (q->rate.rate_bytes_ps != 0 && q->next_available > (now = ktime_get_ns())) {
        // Deny transmission, setup timer for next sending time.
        qdisc_watchdog_schedule_ns(&q->watchdog, q->next_available);
        goto end;
    }

    for (max_loop = 1000; max_loop >= 0 && skb == NULL; max_loop--) {
        if (is_active_leaf(cl) && cl->quota >= 0) {
            skb = cl->leaf.q->dequeue(cl->leaf.q);

            if (skb != NULL) {
                cl->quota -= qdisc_pkt_len(skb);
            } else {
                q->root->quota -= cl->quota;
                deactivate_leaf(cl);
            }
        } else {
            cl = advance_leaf(q, cl);
        }
    }

    q->active_leaf = cl;

    if (skb == NULL) {
        printk(KERN_ERR "No SKB");
    }

end:
    if (skb) {
        qdisc_bstats_update(sch, skb);
        qdisc_qstats_backlog_dec(sch, skb);
        sch->q.qlen--;

        if (q->rate.rate_bytes_ps && !is_direct) {
            q->next_available = now + (s64)psched_l2t_ns(&q->rate, qdisc_pkt_len(skb));
        }
    }

    return skb;
}

static void hdrr_reset(struct Qdisc *sch) {
	struct hdrr_sched *q = qdisc_priv(sch);
	struct hdrr_class *cl;
	unsigned int i;
    int sum_weight = 0;

	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry(cl, &q->clhash.hash[i], common.hnode) {
			if (is_leaf(cl)) {
				qdisc_reset(cl->leaf.q);
                cl->leaf.next_leaf = NULL;
            } else {
                memset(&cl->inner, 0, sizeof(cl->inner));
            }
            cl->drop_count = 0;
            cl->quota = 0;
            sum_weight += cl->weight;
		}
	}
    q->root->quota = sum_weight;
    q->first_leaf = ll_tail;
    q->active_leaf = NULL;
    q->current_round = 1;
    if (q->rate.rate_bytes_ps != 0)
        qdisc_watchdog_cancel(&q->watchdog);
    __qdisc_reset_queue(&q->direct_queue);
	sch->q.qlen = 0;
	sch->qstats.backlog = 0;
}

static const struct nla_policy hdrr_policy[TCA_HDRR_MAX + 1] = {
	[TCA_HDRR_PARMS]	= { .len = sizeof(struct tc_hdrr_opt) },
	[TCA_HDRR_INIT]	= { .len = sizeof(struct tc_hdrr_glob) },
};

static int hdrr_init(struct Qdisc *sch, struct nlattr *opt) {
    struct hdrr_sched *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_HDRR_MAX + 1];
    struct tc_hdrr_glob *gopt;
    struct tc_ratespec rate_spec;

    int err;

    if (!opt)
        return -EINVAL;

    err = tcf_block_get(&q->block, &q->filter_list, sch);
    if (err)
        return err;

    err = nla_parse_nested(tb, TCA_HDRR_MAX, opt, hdrr_policy, NULL);
    if (err < 0)
        return err;

    if (!tb[TCA_HDRR_INIT])
        return -EINVAL;

    err = qdisc_class_hash_init(&q->clhash);
    if (err < 0)
        return err;

    qdisc_skb_head_init(&q->direct_queue);

    gopt = nla_data(tb[TCA_HDRR_INIT]);

	if (gopt->direct_qlen != 0)
		q->direct_qlen = gopt->direct_qlen;
	else
		q->direct_qlen = qdisc_dev(sch)->tx_queue_len;

    q->rate.rate_bytes_ps = gopt->rate;
    if (gopt->rate != 0) {
        memset(&rate_spec, 0, sizeof(rate_spec));
        rate_spec.rate = gopt->rate;
        psched_ratecfg_precompute(&q->rate, &rate_spec, gopt->rate);
        qdisc_watchdog_init(&q->watchdog, sch);
        q->next_available = ktime_get_ns();
    }

    q->default_class = gopt->defcls;
    q->direct_pkts = 0;
    q->active_leaf = NULL;
    q->first_leaf = ll_tail;
    q->root = NULL;
    q->current_round = 1;
    return 0;
}

static int hdrr_change_class(struct Qdisc *sch, u32 classid,
			    u32 parentid, struct nlattr **tca,
			    unsigned long *arg)
{
    int err = -EINVAL;
    struct hdrr_sched *q = qdisc_priv(sch);
    struct hdrr_class *cl = (struct hdrr_class*)*arg, *ancestor;
    struct nlattr *opt = tca[TCA_OPTIONS];
    struct nlattr *tb[TCA_HDRR_MAX + 1];
    struct tc_hdrr_opt *hopt;

    if (!opt)
        goto failure;

    err = nla_parse_nested(tb, TCA_HDRR_MAX, opt, hdrr_policy, NULL);
    if (err < 0)
        goto failure;

    err = -EINVAL;
    if (tb[TCA_HDRR_PARMS] == NULL)
        goto failure;

    ancestor = parentid == TC_H_ROOT ? NULL : hdrr_find(parentid, sch);

    hopt = nla_data(tb[TCA_HDRR_PARMS]);

    if (!cl) {
        struct Qdisc *new_q;

        if (!classid || TC_H_MAJ(classid ^ sch->handle) || hdrr_find(classid, sch))
            goto failure;

        err = -ENOBUFS;
        cl = kzalloc(sizeof(*cl), GFP_KERNEL);
        if (!cl)
            goto failure;

        err = tcf_block_get(&cl->block, &cl->filter_list, sch);
        cl->filter_cnt = 0;
        if (err) {
            kfree(cl);
            goto failure;
        }

        new_q = qdisc_create_dflt(sch->dev_queue, &pfifo_qdisc_ops, classid);

        cl->children_count = 0;
        cl->drop_count = 0;

        cl->common.classid = classid;
        cl->parent = ancestor;

        memset(&cl->leaf, 0, sizeof(cl->leaf));
        cl->leaf.q = new_q ? new_q : &noop_qdisc;

        sch_tree_lock(sch);

        if (ancestor && is_leaf(ancestor)) {
            if (is_leaf(ancestor)) {
                hdrr_leaf_to_internal(ancestor);
            }

            ancestor->children_count += 1;
        }

        qdisc_class_hash_insert(&q->clhash, &cl->common);
        if (cl->leaf.q != &noop_qdisc)
            qdisc_hash_add(cl->leaf.q, true);
    } else {
        sch_tree_lock(sch);
    }

    cl->weight = hopt->weight;
    if (unlikely(q->root == NULL)) {
        q->root = cl;
    }
    q->root->quota += hopt->weight;

    sch_tree_unlock(sch);
    qdisc_class_hash_grow(sch, &q->clhash);
    *arg = (unsigned long)cl;

    return 0;

failure:
    return err;
}

static void hdrr_destroy_class(struct Qdisc *sch, struct hdrr_class *cl) {
    if (is_leaf(cl)) {
        WARN_ON(!cl->leaf.q);
        qdisc_destroy(cl->leaf.q);
    }

    tcf_block_put(cl->block);
    kfree(cl);
}

static void hdrr_destroy(struct Qdisc *sch) {
    struct hdrr_sched *q = qdisc_priv(sch);
    struct hdrr_class *cl;
    struct hlist_node *next;

    int i;

    if (q->rate.rate_bytes_ps != 0)
        qdisc_watchdog_cancel(&q->watchdog);

    tcf_block_put(q->block);

	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry(cl, &q->clhash.hash[i], common.hnode) {
			tcf_block_put(cl->block);
			cl->block = NULL;
		}
	}
	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry_safe(cl, next, &q->clhash.hash[i],
					  common.hnode)
			hdrr_destroy_class(sch, cl);
	}
	qdisc_class_hash_destroy(&q->clhash);
	__qdisc_reset_queue(&q->direct_queue);
}

static int hdrr_delete(struct Qdisc *sch, unsigned long arg)
{
	struct hdrr_sched *q = qdisc_priv(sch);
	struct hdrr_class *cl = (struct hdrr_class *)arg;
	struct Qdisc *new_q = NULL;

    /*
     * TODO: If we want to delete internal class, we can either leave its
     * children be, resulting in splitted forest, or we can recursively delete
     * the children. Either way we need to add more logic.
     */
	if (!is_leaf(cl) || is_attached_leaf(cl) || cl->filter_cnt)
		return -EBUSY;

	sch_tree_lock(sch);

    // Should always be true as is, but keep it here in case we add internal-class logic
	if (is_leaf(cl)) {
		unsigned int qlen = cl->leaf.q->q.qlen;
		unsigned int backlog = cl->leaf.q->qstats.backlog;

		qdisc_reset(cl->leaf.q);
		qdisc_tree_reduce_backlog(cl->leaf.q, qlen, backlog);
	}

	/* delete from hash and active; remainder in destroy_class */
	qdisc_class_hash_remove(&q->clhash, &cl->common);

    if (cl->parent) {
        cl->parent->children_count--;
        if (cl->parent->children_count == 0) {
            new_q = qdisc_create_dflt(sch->dev_queue, &pfifo_qdisc_ops, cl->parent->common.classid);
		    hdrr_internal_to_leaf(q, cl->parent, new_q);
        }
    }

    if (cl == q->root) {
        q->root = NULL;
    } else {
        q->root->quota -= cl->weight;
    }

	sch_tree_unlock(sch);

	hdrr_destroy_class(sch, cl);
	return 0;
}

static struct tcf_block *hdrr_tcf_block(struct Qdisc *sch, unsigned long arg)
{
	struct hdrr_sched *q = qdisc_priv(sch);
	struct hdrr_class *cl = (struct hdrr_class *)arg;

	return cl ? cl->block : q->block;
}

static int hdrr_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		     struct Qdisc **old)
{
    struct hdrr_class *cl = (struct hdrr_class*)arg;

    if (is_leaf(cl)) {
        return -EINVAL;
    }
    if (new == NULL && (new = qdisc_create_dflt(sch->dev_queue, &pfifo_qdisc_ops, cl->common.classid)) == NULL)
        return -ENOBUFS;

    *old = qdisc_replace(sch, new, &cl->leaf.q);
    return 0;
}

static struct Qdisc *hdrr_leaf(struct Qdisc *sch, unsigned long arg)
{
    struct hdrr_class *cl = (struct hdrr_class*)arg;
    return is_leaf(cl) ? cl->leaf.q : NULL;
}

static unsigned long hdrr_bind_filter(struct Qdisc *sch, unsigned long parent,
				     u32 classid)
{
	struct hdrr_class *cl = hdrr_find(classid, sch);

	if (cl)
		cl->filter_cnt++;
	return (unsigned long)cl;
}

static void hdrr_unbind_filter(struct Qdisc *sch, unsigned long arg)
{
	struct hdrr_class *cl = (struct hdrr_class *)arg;

	if (cl)
		cl->filter_cnt--;
}

static void hdrr_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct hdrr_sched *q = qdisc_priv(sch);
	struct hdrr_class *cl;
	unsigned int i;

	if (arg->stop)
		return;

	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry(cl, &q->clhash.hash[i], common.hnode) {
			if (arg->count < arg->skip) {
				arg->count++;
				continue;
			}
			if (arg->fn(sch, (unsigned long)cl, arg) < 0) {
				arg->stop = 1;
				return;
			}
			arg->count++;
		}
	}
}

static int hdrr_dump(struct Qdisc *sch, struct sk_buff *skb) {
    struct hdrr_sched *q = qdisc_priv(sch);
    struct nlattr*nest;
    struct tc_hdrr_glob gopt = {
        .defcls = q->default_class,
        .rate = q->rate.rate_bytes_ps,
        .direct_qlen = q->direct_qlen,
    };

    nest = nla_nest_start(skb, TCA_OPTIONS);
    if (nest == NULL)
        goto failure;

    if (nla_put(skb, TCA_HDRR_INIT, sizeof(gopt), &gopt))
        goto failure;

    return nla_nest_end(skb, nest);
failure:
    nla_nest_cancel(skb, nest);
    return -1;
}

static int hdrr_dump_class(struct Qdisc *sch, unsigned long arg,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	/* Its safe to not acquire qdisc lock. As we hold RTNL,
	 * no change can happen on the class parameters.
	 */
    struct hdrr_class *cl = (struct hdrr_class*)arg;
    struct nlattr *nest;
    struct tc_hdrr_opt opt;

    tcm->tcm_parent = cl->parent ? cl->parent->common.classid : TC_H_ROOT;
    tcm->tcm_handle = cl->common.classid;
    if (is_leaf(cl) && cl->leaf.q)
        tcm->tcm_info = cl->leaf.q->handle;

    nest = nla_nest_start(skb, TCA_OPTIONS);
    if (nest == NULL)
        goto failure;

    opt.weight = cl->weight;
    if (nla_put(skb, TCA_HDRR_PARMS, sizeof(opt), &opt))
        goto failure;

    return nla_nest_end(skb, nest);

failure:
    nla_nest_cancel(skb, nest);
	return -1;
}

static int
hdrr_dump_class_stats(struct Qdisc *sch, unsigned long arg, struct gnet_dump *d)
{
    struct hdrr_class *cl = (struct hdrr_class *)arg;
    struct gnet_stats_queue qs = {
        .drops = cl->drop_count
    };

    __u32 qlen = 0;

    if (is_leaf(cl) && cl->leaf.q) {
        qlen = cl->leaf.q->q.qlen;
        qs.backlog = cl->leaf.q->qstats.backlog;
    }

    if (gnet_stats_copy_basic(qdisc_root_sleeping_running(sch), d, NULL, &cl->basic_stats) < 0 || 
        gnet_stats_copy_queue(d, NULL, &qs, qlen) < 0) {
        return -1;
    }

    return gnet_stats_copy_app(d, &cl->xstats, sizeof(cl->xstats));
}

static const struct Qdisc_class_ops hdrr_class_ops = {
	.graft		=	hdrr_graft,
	.leaf		=	hdrr_leaf,
	.qlen_notify	=	NULL,
	.find		=	hdrr_search,
	.change		=	hdrr_change_class,
	.delete		=	hdrr_delete,
	.walk		=	hdrr_walk,
	.tcf_block	=	hdrr_tcf_block,
	.bind_tcf	=	hdrr_bind_filter,
	.unbind_tcf	=	hdrr_unbind_filter,
	.dump		=   hdrr_dump_class,
	.dump_stats	=   hdrr_dump_class_stats,
};

static struct Qdisc_ops hdrr_qdisc_ops __read_mostly = {
	.cl_ops     =	&hdrr_class_ops,
	.id         =	"hdrr",
	.priv_size  =	sizeof(struct hdrr_sched),
	.enqueue    =	hdrr_enqueue,
	.dequeue    =	hdrr_dequeue,
	.peek       =	qdisc_peek_dequeued,
	.init       =	hdrr_init,
	.reset      =	hdrr_reset,
	.destroy    =	hdrr_destroy,
	.dump       =	hdrr_dump,
	.owner      =	THIS_MODULE,
};

static int __init hdrr_module_init(void)
{
	return register_qdisc(&hdrr_qdisc_ops);
}
static void __exit hdrr_module_exit(void)
{
	unregister_qdisc(&hdrr_qdisc_ops);
}

module_init(hdrr_module_init)
module_exit(hdrr_module_exit)
MODULE_LICENSE("GPL");

