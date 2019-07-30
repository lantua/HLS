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
    __u32 quantum;
};
struct tc_hdrr_glob {
    __u64 rate;   // limited rate of the link
    __u32 qmul;   // quantum multiplier
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

	struct work_struct	work;

	struct hdrr_class	*parent;

	struct gnet_stats_basic_packed  basic_stats;
    struct tc_hdrr_xstats           xstats;

    int children_count, busy_count;
    int quantum, tokens;

    int drop_count;

	union {
		struct {
			struct list_head drop_list;
			struct Qdisc	*q;
            int idle_count_until_remove;

            struct hdrr_class *next_active_leaf;
            struct hdrr_class *prev_active_leaf;
		} leaf;
		struct {
            struct hdrr_class *first_active_leaf;
            struct hdrr_class *last_active_leaf;
            int total_quantum;
            int accrued_quantum;
		} inner;
	};
};

struct hdrr_sched {
	struct Qdisc_class_hash clhash;
	int			default_class;		/* class where unclassified flows go to */

	/* filters for qdisc itself */
	struct tcf_proto __rcu	*filter_list;
	struct tcf_block	*block;

	int			direct_qlen;
    int quantum_multiplier;

	/* non shaped skbs; let them go directly thru */
	struct qdisc_skb_head	direct_queue;
	long			direct_pkts;

    struct hdrr_class *active_class;
};

static inline int is_leaf(struct hdrr_class *cl) { return cl->children_count == 0; }
static inline int is_busy(struct hdrr_class *cl) { return cl->busy_count != 0; }
static inline int is_active_inner(struct hdrr_class *cl) { return cl->inner.first_active_leaf != NULL; }
static inline int is_active_leaf(struct hdrr_class *cl) { return cl->leaf.next_active_leaf != NULL; }

static inline void activate_leaf(struct hdrr_class *cl) {
    struct hdrr_class* first = NULL;
    struct hdrr_class* ancestor;

    for (ancestor = cl->parent; (ancestor != NULL) && !is_active_inner(ancestor); ancestor = ancestor->parent) {
        // Inactive ancestor
        ancestor->inner.first_active_leaf = cl;
        ancestor->inner.last_active_leaf = cl;
    }
    if (ancestor != NULL) {
        // First active ancestor
        // Retrieve `first` leaf of the tree
        // Then append `cl` *before* `first`
        first = ancestor->inner.first_active_leaf;

        cl->leaf.next_active_leaf = first;
        cl->leaf.prev_active_leaf = first->leaf.prev_active_leaf;
        cl->leaf.prev_active_leaf->leaf.next_active_leaf = cl;
        first->leaf.prev_active_leaf = cl;
    } else {
        // First active class, ever
        cl->leaf.next_active_leaf = cl;
        cl->leaf.prev_active_leaf = cl;
    }
    // Active ancestors, make sure `cl` is before `first`
    for (; (ancestor != NULL) && ancestor->inner.first_active_leaf == first; ancestor = ancestor->parent) {
        ancestor->inner.first_active_leaf = cl;
    }
}

static inline void deactivate_leaf(struct hdrr_class *cl) {
    struct hdrr_class *ancestor;
    struct hdrr_class *next = cl->leaf.next_active_leaf;
    struct hdrr_class *prev = cl->leaf.prev_active_leaf;

    next->leaf.prev_active_leaf = prev;
    prev->leaf.next_active_leaf = next;

    cl->leaf.next_active_leaf = NULL;
    cl->leaf.prev_active_leaf = NULL;
    cl->xstats.deactivate_count += 1;

    for (ancestor = cl->parent; ancestor != NULL; ancestor = ancestor->parent) {
        if (ancestor->inner.first_active_leaf == cl) {
            if (ancestor->inner.last_active_leaf == cl) {
                // Both match, deactivate ancestor
                cl->xstats.deactivate_count += 1;
                ancestor->inner.first_active_leaf = NULL;
                ancestor->inner.last_active_leaf = NULL;
            } else {
                // Only first leaf match
                ancestor->inner.first_active_leaf = next;
            }
        } else {
            if (ancestor->inner.last_active_leaf == cl) {
                // Only last leaf match
                ancestor->inner.last_active_leaf = prev;
            } else {
                // No match
                break;
            }
        }
    }
}

static inline void mark_busy_leaf(struct hdrr_class *cl) {
    struct hdrr_class* ancestor;
    int quantum = cl->quantum;

    cl->busy_count = 1;

    for (ancestor = cl->parent; (ancestor != NULL) && !is_busy(ancestor); ancestor = ancestor->parent) {
        // Idle ancestor
        ancestor->busy_count = 1;

        ancestor->inner.accrued_quantum -= quantum;
        quantum += ancestor->inner.accrued_quantum;
    }

    // First busy ancestor
    if (ancestor != NULL) {
        ancestor->busy_count += 1;
        ancestor->inner.accrued_quantum -= quantum;
    }
}

static inline void mark_idle_leaf(struct hdrr_class *cl) {
    struct hdrr_class* ancestor;
    int quantum = cl->quantum;
    int tokens = cl->tokens;

    cl->busy_count = 0;
    cl->xstats.mark_idle_count += 1;
    cl->tokens = 0;


    for (ancestor = cl->parent; (ancestor != NULL) && ancestor->busy_count == 1; ancestor = ancestor->parent) {
        // Ancestor with `cl` as only busy leaf, and so will turn idle if `cl` turns idle
        ancestor->busy_count = 0;
        ancestor->xstats.mark_idle_count += 1;

        ancestor->inner.accrued_quantum += quantum;
        quantum = ancestor->inner.accrued_quantum;

        tokens += ancestor->tokens;
        ancestor->tokens = 0;
    }

    // First ancestor to stay busy
    if (ancestor) {
        ancestor->busy_count -= 1;
        ancestor->inner.accrued_quantum += quantum;
        ancestor->tokens += tokens;
    }
}

static inline struct hdrr_class* advance_leaf(struct hdrr_class* cl) {
    struct hdrr_class *ancestor;

    cl->tokens += cl->quantum;

    for (ancestor = cl->parent; (ancestor != NULL) && ancestor->inner.last_active_leaf == cl; ancestor = ancestor->parent) {
        ancestor->tokens += ancestor->inner.accrued_quantum;
        
        if (ancestor->tokens >= 0) {
            ancestor->tokens -= ancestor->inner.total_quantum;
            return ancestor->inner.first_active_leaf;
        }
    }

    return cl->leaf.next_active_leaf;
}

static inline void hdrr_internal_to_leaf(struct hdrr_sched *q, struct hdrr_class *cl,
			       struct Qdisc *new_q) {
    // TODO: Could we safely assume class is idle?
    memset(&cl->leaf, 0, sizeof(cl->leaf));

    INIT_LIST_HEAD(&cl->leaf.drop_list);
    cl->leaf.q = new_q ? new_q : &noop_qdisc;
}

static inline void hdrr_leaf_to_internal(struct hdrr_sched *q, struct hdrr_class *cl) {
    // TODO: Could we safely assume class is idle? Does it even make sense for these kind of class to be backlogged?
    unsigned int qlen = cl->leaf.q->q.qlen;
    unsigned int backlog = cl->leaf.q->qstats.backlog;

    qdisc_reset(cl->leaf.q);
    qdisc_tree_reduce_backlog(cl->leaf.q, qlen, backlog);
    qdisc_destroy(cl->leaf.q);

    memset(&cl->inner, 0, sizeof(cl->inner));
    cl->inner.accrued_quantum = cl->quantum;
    cl->inner.total_quantum = cl->quantum;
}

static inline struct hdrr_class *hdrr_find(u32 handle, struct Qdisc *sch)
{
	struct hdrr_sched *q = qdisc_priv(sch);
	struct Qdisc_class_common *clc;

	clc = qdisc_class_find(&q->clhash, handle);
	if (clc == NULL)
		return NULL;

	return container_of(clc, struct hdrr_class, common);
}

static unsigned long hdrr_search(struct Qdisc *sch, u32 handle)
{
	return (unsigned long)hdrr_find(handle, sch);
}

static struct hdrr_class *hdrr_classify(struct sk_buff *skb, struct Qdisc *sch,
				      int *qerr) {
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
		qh->tail = skb;
	} else {
		qh->tail = skb;
		qh->head = skb;
	}
	qh->qlen++;
}
static int hdrr_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		       struct sk_buff **to_free)
{
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
            return qdisc_drop(skb, sch, to_free);
        }
    }

    if ((ret = qdisc_enqueue(skb, cl->leaf.q, to_free)) != NET_XMIT_SUCCESS) {
        if (net_xmit_drop_count(ret)) {
            qdisc_qstats_drop(sch);
            cl->drop_count++;
        }
        return ret;
    }

    if (!is_busy(cl)) {
        if (!is_active_leaf(cl)) {
            activate_leaf(cl);
        }
        mark_busy_leaf(cl);
        if (unlikely(q->active_class == NULL)) {
            q->active_class = cl;
        }
    }

succeed:
    qdisc_qstats_backlog_inc(sch, skb);
    sch->q.qlen++;
    return NET_XMIT_SUCCESS;
}

static struct sk_buff *hdrr_dequeue(struct Qdisc *sch) {
    struct hdrr_sched *q = qdisc_priv(sch);
    struct hdrr_class *cl = q->active_class;
    struct hdrr_class *prev;

    struct sk_buff *skb = NULL;

	skb = __qdisc_dequeue_head(&q->direct_queue);
	if (skb != NULL || !sch->q.qlen || !cl)
		goto end;

    // Since sch->q.qlen != 0, we are guaranteed to have at least one packet.
    do {
        if (is_busy(cl)) {
            if (cl->tokens < 0) {
                cl = advance_leaf(cl);
                continue;
            }

            skb = cl->leaf.q->dequeue(cl->leaf.q);
            if (likely(skb != NULL)) {
                cl->tokens -= qdisc_pkt_len(skb);
            } else {
                mark_idle_leaf(cl);
                cl = advance_leaf(cl);
            }
        } else {
            cl->leaf.idle_count_until_remove -= 1;
            if (cl->leaf.idle_count_until_remove < 0) {
                prev = cl;
                cl = advance_leaf(cl);
                deactivate_leaf(prev);
            } else {
                cl = advance_leaf(cl);
            }
        }
    } while (skb == NULL);
    q->active_class = advance_leaf(cl);

end:
    if (skb) {
        qdisc_bstats_update(sch, skb);
        qdisc_qstats_backlog_dec(sch, skb);
        sch->q.qlen--;
    }
    return skb;
}

static void hdrr_reset(struct Qdisc *sch) {
	struct hdrr_sched *q = qdisc_priv(sch);
	struct hdrr_class *cl;
	unsigned int i;

    printk(KERN_DEBUG "Resetting");

	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry(cl, &q->clhash.hash[i], common.hnode) {
			if (is_leaf(cl)) {
				qdisc_reset(cl->leaf.q);
			    INIT_LIST_HEAD(&cl->leaf.drop_list);

                cl->leaf.next_active_leaf = NULL;
                cl->leaf.prev_active_leaf = NULL;
            } else {
                cl->inner.first_active_leaf = NULL;
                cl->inner.last_active_leaf = NULL;
                cl->inner.accrued_quantum = cl->inner.total_quantum;
            }
            cl->busy_count = 0;
            cl->tokens = 0;
            cl->drop_count = 0;
		}
	}
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

    int err;

    printk(KERN_DEBUG "Initing");

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

    q->default_class = gopt->defcls;
    q->quantum_multiplier = gopt->qmul;
    q->direct_pkts = 0;
    q->active_class = NULL;
    return 0;
}

static int hdrr_change_class(struct Qdisc *sch, u32 classid,
			    u32 parentid, struct nlattr **tca,
			    unsigned long *arg)
{
    int err = -EINVAL, quantum_diff;
    struct hdrr_sched *q = qdisc_priv(sch);
    struct hdrr_class *cl = (struct hdrr_class*)*arg, *ancestor;
    struct nlattr *opt = tca[TCA_OPTIONS];
    struct nlattr *tb[TCA_HDRR_MAX + 1];
    struct tc_hdrr_opt *hopt;

    printk(KERN_DEBUG "Changing %d %p %p", classid, cl, opt);

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
        cl->tokens = 0;
        quantum_diff = 0;

        cl->common.classid = classid;
        cl->parent = ancestor;

        memset(&cl->leaf, 0, sizeof(cl->leaf));
        INIT_LIST_HEAD(&cl->leaf.drop_list);
        cl->leaf.q = new_q ? new_q : &noop_qdisc;

        sch_tree_lock(sch);

        if (ancestor && is_leaf(ancestor)) {
            if (is_leaf(ancestor)) {
                hdrr_leaf_to_internal(q, ancestor);
            }

            ancestor->children_count += 1;
        }

        qdisc_class_hash_insert(&q->clhash, &cl->common);
        if (cl->leaf.q != &noop_qdisc)
            qdisc_hash_add(cl->leaf.q, true);
    } else {
        sch_tree_lock(sch);
        quantum_diff = -cl->quantum;
    }

    printk(KERN_DEBUG "Changing %d", cl->common.classid);

    cl->quantum = hopt->quantum * q->quantum_multiplier;
    quantum_diff += cl->quantum;
    for (; (ancestor != NULL) && !is_active_inner(ancestor); ancestor = ancestor->parent) {
        ancestor->inner.accrued_quantum += quantum_diff;
        ancestor->inner.total_quantum += quantum_diff;
    }
    if (ancestor != NULL) {
        ancestor->inner.accrued_quantum += quantum_diff;
    }
    for (; ancestor != NULL; ancestor = ancestor->parent) {
        ancestor->inner.total_quantum += quantum_diff;
    }

    sch_tree_unlock(sch);
    qdisc_class_hash_grow(sch, &q->clhash);
    *arg = (unsigned long)cl;
    return 0;

failure:
    return err;
}

static void hdrr_destroy_class(struct Qdisc *sch, struct hdrr_class *cl) {
    printk(KERN_DEBUG "Destroying %d", cl->common.classid);

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

    printk(KERN_DEBUG "Destroying qdisc");
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

    printk(KERN_DEBUG "Deleting %d", cl->common.classid);
	/* TODO: why don't allow to delete subtree ? references ? does
	 * tc subsys guarantee us that in hdrr_destroy it holds no class
	 * refs so that we can remove children safely there ?
	 */
	if (cl->filter_cnt)
		return -EBUSY;

	sch_tree_lock(sch);

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

    printk(KERN_DEBUG "Grafting %d", cl->common.classid);

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
        .qmul = q->quantum_multiplier,
        .defcls = q->default_class,
        .direct_qlen = q->direct_qlen,
    };

    printk(KERN_DEBUG "Dumping qdisc");

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

    printk(KERN_DEBUG "Dumping %d", cl->common.classid);

    tcm->tcm_parent = cl->parent ? cl->parent->common.classid : TC_H_ROOT;
    tcm->tcm_handle = cl->common.classid;
    if (is_leaf(cl) && cl->leaf.q)
        tcm->tcm_info = cl->leaf.q->handle;

    nest = nla_nest_start(skb, TCA_OPTIONS);
    if (nest == NULL)
        goto failure;

    opt.quantum = cl->quantum;
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

    printk(KERN_DEBUG "Dumping %d stats", cl->common.classid);

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
    //printk(KERN_DEBUG "Starting HDRR");
	return register_qdisc(&hdrr_qdisc_ops);
}
static void __exit hdrr_module_exit(void)
{
    //printk(KERN_DEBUG "Stopping HDRR");
	unregister_qdisc(&hdrr_qdisc_ops);
}

module_init(hdrr_module_init)
module_exit(hdrr_module_exit)
MODULE_LICENSE("GPL");
