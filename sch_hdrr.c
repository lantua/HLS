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

            int is_active;

            struct hdrr_class *next_leaf;
            struct hdrr_class *prev_leaf;
		} leaf;
		struct {
            int active_weight; // sum of weight of active & busy children
            int fairshare;
            int fairshare_threshold; // smallest value of `fairshare` to trigger distribution

            struct hdrr_class *first_leaf;
            struct hdrr_class *last_leaf;

            struct hdrr_class *next_subtree;
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
    struct hdrr_class *active_class;
    struct hdrr_class *root;
    struct hdrr_class *current_subtree;
};

static inline bool hdrr_verify(struct hdrr_sched* q);

static inline int div_round_up(int numerator, int denominator) {
    WARN_ON(denominator == 0);
    return (numerator + denominator - 1) / denominator;
}

static inline bool is_leaf(struct hdrr_class *cl) { return cl->children_count == 0; }

static inline bool is_active_leaf(struct hdrr_class *cl) { return cl->leaf.is_active; }
static inline bool is_active_inner(struct hdrr_class *cl) { return cl->inner.active_weight != 0; }

static inline bool is_attached_leaf(struct hdrr_class *cl) { return cl->leaf.next_leaf != NULL; }
static inline bool is_attached_inner(struct hdrr_class *cl) { return cl->inner.first_leaf != NULL; }

static inline unsigned int classid(struct hdrr_class *cl) { return cl->common.classid & 0xffff; }

static inline int required_quota_inner(struct hdrr_class *ancestor) {
    return ancestor->inner.fairshare_threshold * ancestor->inner.active_weight - ancestor->quota;
}

static inline void take_quota(struct hdrr_class *cl) {
    WARN_ON(cl == NULL);
    cl->quota += cl->parent->inner.fairshare * cl->weight;
    printk("Add quota to %u Q%+d (%d)", classid(cl), cl->parent->inner.fairshare * cl->weight, cl->quota);
}

#define set_threshold(x, y) set_threshold_imp(x, y, __LINE__)

static inline void set_threshold_imp(struct hdrr_class *ancestor, int candidate, int line_number) {
    WARN_ON(ancestor == NULL);
    WARN_ON(candidate < 0);

    if (ancestor->inner.fairshare_threshold > candidate) {
        ancestor->inner.fairshare_threshold = candidate;
    }
    //printk(KERN_DEBUG "Setting threshold of %u to %d, uses %d", classid(ancestor), candidate, ancestor->inner.fairshare_threshold);
}

static inline void add_subtree(struct hdrr_sched *q, struct hdrr_class *cl) {
    WARN_ON(cl == NULL);
    if (cl->inner.next_subtree == NULL) {
        cl->inner.next_subtree = q->current_subtree->inner.next_subtree;
        q->current_subtree->inner.next_subtree = cl;
        //printk(KERN_DEBUG "Inserting subtree %u", classid(cl));
    }
}

static inline void advance_subtree(struct hdrr_sched *q) {
    struct hdrr_class *tmp;
    int max_loop = 5;

    while (required_quota_inner(q->current_subtree) > 0 && is_active_inner(q->current_subtree) && max_loop-- >= 0) {
        tmp = q->current_subtree;
        q->current_subtree = NULL;// tmp->inner.next_subtree; // TODO: Change back
        tmp->inner.next_subtree = NULL;

        if (q->current_subtree == NULL) {
            const int round_size = 1000;
            const int required = required_quota_inner(q->root);
            const int added = div_round_up(required, round_size) * round_size;
            q->root->quota += added;
            q->current_subtree = q->root;
            printk(KERN_DEBUG "Root threshold %d, required %d, Q%+d (%d)", q->root->inner.fairshare_threshold, required, added, q->root->quota);
            break;
        }
    }
    //printk(KERN_DEBUG "Advanced subtree to %u", classid(q->current_subtree));
}

static inline void attach_leaf(struct hdrr_class *cl) {
    struct hdrr_class* old_first;
    struct hdrr_class* ancestor;

    WARN_ON(cl == NULL);

    if (is_attached_leaf(cl)) {
        //printk(KERN_ERR "Attaching attached %u", classid(cl));
        return;
    }

    //printk(KERN_DEBUG "Attaching %u", classid(cl));

    for (ancestor = cl->parent; ancestor != NULL && !is_attached_inner(ancestor); ancestor = ancestor->parent) {
        // Unattached ancestor
        ancestor->inner.first_leaf = cl;
        ancestor->inner.last_leaf = cl;
    }
    if (likely(ancestor != NULL)) {
        // First attached ancestor
        // append `cl` before `first_leaf`
        old_first = ancestor->inner.first_leaf;

        cl->leaf.prev_leaf = old_first->leaf.prev_leaf;
        cl->leaf.next_leaf = old_first;
        old_first->leaf.prev_leaf->leaf.next_leaf = cl;
        old_first->leaf.prev_leaf = cl;
        for (; (ancestor != NULL) && ancestor->inner.first_leaf == old_first; ancestor = ancestor->parent) {
            ancestor->inner.first_leaf = cl;
        }

        //printk(KERN_DEBUG "Attached %u before %u", classid(cl), classid(old_first));
    } else {
        // First active leaf in the entire tree
        cl->leaf.next_leaf = cl;
        cl->leaf.prev_leaf = cl;

        //printk(KERN_DEBUG "First Attached %u", classid(cl));
    }
}

static inline void detach_leaf(struct hdrr_class *cl) {
    struct hdrr_class* ancestor;

    WARN_ON(cl == NULL);

    if (!is_attached_leaf(cl)) {
        //printk(KERN_ERR "Detaching unattached %u", classid(cl));
        return;
    }

    //printk(KERN_DEBUG "Detaching %u", classid(cl));

    for (ancestor = cl->parent; ancestor != NULL && ancestor->inner.first_leaf == cl && ancestor->inner.last_leaf == cl; ancestor = ancestor->parent) {
        // Only child, detach ancestor
        ancestor->inner.first_leaf = NULL;
        ancestor->inner.last_leaf = NULL;
    }

    if (likely(ancestor != NULL)) {
        if (ancestor->inner.first_leaf == cl) {
            // First child
            for (; ancestor != NULL && ancestor->inner.first_leaf == cl; ancestor = ancestor->parent) {
                ancestor->inner.first_leaf = cl->leaf.next_leaf;
            }
        } else {
            // Last child
            for (; ancestor != NULL && ancestor->inner.last_leaf == cl; ancestor = ancestor->parent) {
                ancestor->inner.last_leaf = cl->leaf.prev_leaf;
            }
        }
    }

    cl->leaf.next_leaf->leaf.prev_leaf = cl->leaf.prev_leaf;
    cl->leaf.prev_leaf->leaf.next_leaf = cl->leaf.next_leaf;
    cl->leaf.next_leaf = NULL;
    cl->leaf.prev_leaf = NULL;

    //printk(KERN_DEBUG "Detached %u", classid(cl));
}

static inline void activate_leaf(struct hdrr_class *cl) {
    struct hdrr_class* ancestor;
    int weight = cl->weight;

    WARN_ON(cl == NULL);

    //printk(KERN_DEBUG "Activating %u", classid(cl));

    cl->leaf.is_active = true;

    for (ancestor = cl->parent; ancestor != NULL && ancestor->inner.active_weight == 0; ancestor = ancestor->parent) {
        // Inactive ancestor
        ancestor->inner.active_weight = weight;
        set_threshold(ancestor, 0);
        weight = ancestor->weight;
    }

    if (ancestor != NULL) {
        // First active ancestor
        ancestor->inner.active_weight += weight;
        set_threshold(ancestor, 0);
    }

    //printk(KERN_DEBUG "Activated %u q %d", classid(cl), cl->quota);
}

static inline void deactivate_leaf(struct hdrr_class *cl) {
    struct hdrr_class* ancestor;
    int weight = cl->weight;

    int quota = cl->quota;
    cl->quota = 0;

    WARN_ON(cl == NULL);

    //printk(KERN_DEBUG "Deactivating %u", classid(cl));

    //printk(KERN_DEBUG "Quota = %d from %u", quota, classid(cl));

    cl->xstats.mark_idle_count += 1;
    cl->leaf.is_active = false;

    for (ancestor = cl->parent; ancestor != NULL && ancestor->inner.active_weight == weight; ancestor = ancestor->parent) {
        // Ancestor with only `cl` as active leaf, deactivate it
        quota += ancestor->quota;
        //printk(KERN_DEBUG "Q += %d, from %u", ancestor->quota, classid(ancestor));
        ancestor->quota = 0;

        weight = ancestor->weight;
        ancestor->inner.active_weight = 0;
    }
    if (ancestor != NULL) {
        // Ancestor that remains active
        ancestor->inner.active_weight -= weight;
        ancestor->quota += quota;
        printk(KERN_INFO "Donate to %u Q%+d (%d)", classid(ancestor), quota, ancestor->quota);
    }

    //printk(KERN_DEBUG "Deactivated %u", classid(cl));
}

static struct hdrr_class* enter_leaf(struct hdrr_class* subtree, struct hdrr_class* ancestor, struct hdrr_class *cl) {
    struct hdrr_class* result = NULL;

    WARN_ON(ancestor == NULL);

    if ((ancestor->inner.first_leaf == cl) != (ancestor->inner.fairshare == -1))
        printk(KERN_ERR "Error at line %d ancestor %u class %u", __LINE__, classid(ancestor), classid(cl));

    if (ancestor->inner.fairshare != -1) {
        return NULL;
    }

    //printk(KERN_DEBUG "Entering %u", classid(ancestor));
    if (ancestor != subtree) {
        if (ancestor->parent == NULL) {
            if (subtree != NULL) {
                printk(KERN_ERR "Bad subtree %u, ancestor %u, cl %u", classid(subtree), classid(ancestor), classid(cl));
            } else {
                printk(KERN_ERR "Bad subtree -, ancestor %u, cl %u", classid(ancestor), classid(cl));
            }
        }
        WARN_ON(ancestor->parent == NULL);
        result = enter_leaf(subtree, ancestor->parent, cl);

        if (!is_active_inner(ancestor)) {
            return result ? result : ancestor;
        }

        if (result == NULL) {
            take_quota(ancestor);
        }
    }

    if (required_quota_inner(ancestor) > 0) {
        // Doesn't reach threshold.
        printk(KERN_DEBUG "Doesn't meet threshold of %d at subtree %u, have %d", ancestor->inner.fairshare_threshold * ancestor->inner.active_weight, classid(ancestor), ancestor->quota);
        return result ? result : ancestor;
    }

    WARN_ON(ancestor->inner.active_weight == 0);

    ancestor->inner.fairshare_threshold = 0x7fffffff;
    ancestor->inner.fairshare = ancestor->quota / ancestor->inner.active_weight;
    ancestor->quota %= ancestor->inner.active_weight;
    printk("Set fairshare of %u to %d (ac %d)", classid(ancestor), ancestor->inner.fairshare, ancestor->inner.active_weight);

    return NULL;
}

static void leave_leaf(struct hdrr_sched* q, struct hdrr_class* ancestor, struct hdrr_class *cl) {
    WARN_ON(ancestor == NULL || cl == NULL);
        
    for (; ancestor->parent != NULL && cl == ancestor->inner.last_leaf; ancestor = ancestor->parent) {
        const int wanted = required_quota_inner(ancestor);

        //printk(KERN_DEBUG "Leaving %u", classid(ancestor));

        if (wanted > 0) {
            set_threshold(ancestor->parent, div_round_up(wanted, ancestor->weight));
        } else {
            set_threshold(ancestor->parent, 0);
            add_subtree(q, ancestor);
        }

        ancestor->inner.fairshare = -1;
    }

    if (ancestor->inner.last_leaf == cl) {
        //printk(KERN_DEBUG "Leaving root %u", classid(ancestor));
        ancestor->inner.fairshare = -1;
    }

    //printk(KERN_DEBUG "Left %u, stop at %u with last class %u", classid(cl), classid(ancestor), classid(ancestor->inner.last_leaf));
}

static inline struct hdrr_class* advance_leaf(struct hdrr_sched* q, struct hdrr_class* cl) {
    int max_loop = 20;
    struct hdrr_class* ancestor;

    WARN_ON(cl == NULL);

    if (unlikely(cl->parent == NULL)) {
        // Single-class hierarchy
        cl->quota = 0x7fffffff;
        return cl;
    }

    //printk(KERN_DEBUG "Advancing from %u", classid(cl));

    ancestor = cl->parent;
    if (cl->quota < 0) {
        set_threshold(ancestor, div_round_up(-cl->quota, cl->weight));
    }

    do {
        WARN_ON(ancestor == NULL);
        //printk(KERN_DEBUG "Leaving leaf %u (%u)", classid(cl), classid(ancestor));
        leave_leaf(q, ancestor, cl);
        //printk(KERN_DEBUG "Left leaf %u (%u)", classid(cl), classid(ancestor));
        if (q->current_subtree->inner.last_leaf == cl) {
            advance_subtree(q);
            if (q->current_subtree->inner.first_leaf == NULL) {
                printk(KERN_ERR "Error at line %d on subtree %u", __LINE__, classid(q->current_subtree));
                return cl;
            }
            cl = q->current_subtree->inner.first_leaf;
        } else {
            cl = cl->leaf.next_leaf;
        }

        //printk(KERN_DEBUG "Entering leaf %u (%u)", classid(cl), classid(cl->parent));
        WARN_ON(cl->parent == NULL);
        ancestor = enter_leaf(q->current_subtree, cl->parent, cl);
        //printk(KERN_DEBUG "Entered result %u", ancestor ? classid(ancestor) : 0);

        if (ancestor != NULL) {
            WARN_ON(cl == NULL);
            cl = ancestor->inner.last_leaf;
        }
    } while (ancestor != NULL && --max_loop >= 0);

    //printk(KERN_DEBUG "Settled at %u", classid(cl));

    if (ancestor == NULL && is_active_leaf(cl)) {
        //printk(KERN_DEBUG "QQ at %u", classid(cl));
        take_quota(cl);
    }

    //printk(KERN_DEBUG "Advanced to %u->%u->%u", classid(cl), classid(cl->leaf.next_leaf), classid(cl->leaf.next_leaf->leaf.next_leaf));

    return cl;
}

static inline void hdrr_internal_to_leaf(struct hdrr_sched *q, struct hdrr_class *cl,
			       struct Qdisc *new_q) {
    WARN_ON(is_attached_inner(cl));
    WARN_ON(is_active_inner(cl));

    //printk(KERN_DEBUG "INTERNAL->LEAF %u", classid(cl));

    memset(&cl->leaf, 0, sizeof(cl->leaf));

    cl->leaf.q = new_q ? new_q : &noop_qdisc;
}

static inline void hdrr_leaf_to_internal(struct hdrr_class *cl) {
    unsigned int qlen = cl->leaf.q->q.qlen;
    unsigned int backlog = cl->leaf.q->qstats.backlog;

    WARN_ON(is_attached_leaf(cl));
    WARN_ON(is_active_leaf(cl));

    qdisc_reset(cl->leaf.q);
    qdisc_tree_reduce_backlog(cl->leaf.q, qlen, backlog);
    qdisc_destroy(cl->leaf.q);

    memset(&cl->inner, 0, sizeof(cl->inner));
    cl->inner.fairshare = -1;
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
    //printk(KERN_DEBUG "SEARCH %u", handle);
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

    if (!is_active_leaf(cl)) {
        if (!is_attached_leaf(cl)) {
            attach_leaf(cl);
        }
        activate_leaf(cl);

        if (unlikely(q->active_class == NULL)) {
            q->active_class = cl;
            if (cl->parent != NULL) {
                struct hdrr_class* bad_subtree;
                bad_subtree = enter_leaf(q->current_subtree, cl->parent, cl);

                WARN_ON(bad_subtree != NULL);
            }
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

    if (!hdrr_verify(q)) {
        goto end;
    }

    for (max_loop = 1000; max_loop >= 0 && skb == NULL; max_loop--) {
        WARN_ON(cl == NULL);
        if (is_active_leaf(cl)) {
            if (cl->quota < 0) {
                cl = advance_leaf(q, cl);
                continue;
            }

            skb = cl->leaf.q->dequeue(cl->leaf.q);

            if (skb != NULL) {
                cl->quota -= qdisc_pkt_len(skb);
            } else {
                deactivate_leaf(cl);
            }
        } else {
            prev = cl;
            cl = advance_leaf(q, prev);
            WARN_ON(cl == NULL);

            detach_leaf(prev);
            if (prev == cl) {
                printk(KERN_ERR "Lost last active class");
                cl = NULL;
                break;
            }
        }
    }

    q->active_class = cl;

    if (skb == NULL) {
        printk(KERN_ERR "No SKB");
    }

end:
    if (skb) {
        //printk(KERN_DEBUG "Dequeued");
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

    printk(KERN_DEBUG "Resetting");

	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry(cl, &q->clhash.hash[i], common.hnode) {
			if (is_leaf(cl)) {
				qdisc_reset(cl->leaf.q);

                cl->leaf.is_active = false;
                cl->leaf.next_leaf = NULL;
                cl->leaf.prev_leaf = NULL;
            } else {
                memset(&cl->inner, 0, sizeof(cl->inner));
                cl->inner.fairshare = -1;
            }
            cl->drop_count = 0;
            cl->quota = 0;
		}
	}
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
    q->active_class = NULL;
    q->root = NULL;
    q->current_subtree = NULL;
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

    //printk(KERN_DEBUG "CHANGE %u", classid);

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
        q->current_subtree = cl;
    }

    sch_tree_unlock(sch);
    qdisc_class_hash_grow(sch, &q->clhash);
    *arg = (unsigned long)cl;

    return 0;

failure:
    return err;
}

static void hdrr_destroy_class(struct Qdisc *sch, struct hdrr_class *cl) {
    printk(KERN_DEBUG "DESTROY %u", classid(cl));

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

    printk(KERN_DEBUG "DELETE %u", classid(cl));

    /*
     * TODO: If we want to delete internal class, we can either leave its
     * children be, resulting in splitted forest, or we can recursively delete
     * the children. Either way we need to add more logic.
     */
	if (!is_leaf(cl) || cl->filter_cnt)
		return -EBUSY;

	sch_tree_lock(sch);

    // Should always be true as is, but keep it here in case we add internal-class logic
	if (is_leaf(cl)) {
		unsigned int qlen = cl->leaf.q->q.qlen;
		unsigned int backlog = cl->leaf.q->qstats.backlog;

		qdisc_reset(cl->leaf.q);
		qdisc_tree_reduce_backlog(cl->leaf.q, qlen, backlog);

        if (is_active_leaf(cl)) {
            deactivate_leaf(cl);
        }
        if (is_attached_leaf(cl)) {
            if (q->active_class == cl) {
                q->active_class = cl->leaf.next_leaf;
                if (q->active_class == cl) {
                    q->active_class = NULL;
                }
            }
            detach_leaf(cl);
        }
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
        q->current_subtree = NULL;
    }

	sch_tree_unlock(sch);

	hdrr_destroy_class(sch, cl);
	return 0;
}

static struct tcf_block *hdrr_tcf_block(struct Qdisc *sch, unsigned long arg)
{
	struct hdrr_sched *q = qdisc_priv(sch);
	struct hdrr_class *cl = (struct hdrr_class *)arg;

    //printk(KERN_DEBUG "TCF BLOCK %u", cl ? classid(cl) : 0);

	return cl ? cl->block : q->block;
}

static int hdrr_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		     struct Qdisc **old)
{
    struct hdrr_class *cl = (struct hdrr_class*)arg;

    printk(KERN_DEBUG "GRAFT %u", classid(cl));

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
    printk(KERN_DEBUG "LEAF %u", classid(cl));
    return is_leaf(cl) ? cl->leaf.q : NULL;
}

static unsigned long hdrr_bind_filter(struct Qdisc *sch, unsigned long parent,
				     u32 classid)
{
	struct hdrr_class *cl = hdrr_find(classid, sch);
    //printk(KERN_DEBUG "BIND %u", classid);

	if (cl)
		cl->filter_cnt++;
	return (unsigned long)cl;
}

static void hdrr_unbind_filter(struct Qdisc *sch, unsigned long arg)
{
	struct hdrr_class *cl = (struct hdrr_class *)arg;
    //printk(KERN_DEBUG "UNBIND %u", classid(cl));

	if (cl)
		cl->filter_cnt--;
}

static void hdrr_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct hdrr_sched *q = qdisc_priv(sch);
	struct hdrr_class *cl;
	unsigned int i;

    printk(KERN_DEBUG "WALK");

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

    //printk(KERN_DEBUG "DUMP QDISC");

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

    //printk(KERN_DEBUG "DUMP %u", classid(cl));

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

    //printk(KERN_DEBUG "DUMPSTAT %u", classid(cl));

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

static inline bool hdrr_verify(struct hdrr_sched *q) {
    int cycle_size = -1;
	struct hdrr_class *cl;
	unsigned int i;
    bool reached[20];
    bool past[20];
    struct hdrr_class* ancestor;

    memset(reached, 0, sizeof(reached));
    memset(past, 0, sizeof(past));

	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry(cl, &q->clhash.hash[i], common.hnode) {
            if (is_leaf(cl)) {
                for (ancestor = cl->parent; ancestor->parent != NULL; ancestor = ancestor->parent);
                if(ancestor != q->root) {
                    printk(KERN_ERR "Verification failed at line %d for %u", __LINE__, classid(cl));
                    return false;
                }

                if (is_active_leaf(cl) && !is_attached_leaf(cl)) {
                    printk(KERN_ERR "Verification failed at line %d for %u", __LINE__, classid(cl));
                    return false;
                }
                if (!cl->leaf.next_leaf != !cl->leaf.prev_leaf) {
                    printk(KERN_ERR "Verification failed at line %d for %u", __LINE__, classid(cl));
                    return false;
                }
                if (cl->leaf.next_leaf && cl->leaf.next_leaf->leaf.prev_leaf != cl) {
                    printk(KERN_ERR "Verification failed at line %d for %u", __LINE__, classid(cl));
                    return false;
                }
                if (cl->leaf.prev_leaf && cl->leaf.prev_leaf->leaf.next_leaf != cl) {
                    printk(KERN_ERR "Verification failed at line %d for %u", __LINE__, classid(cl));
                    return false;
                }
                if (cl->leaf.next_leaf) {
                    struct hdrr_class* tmp = cl->leaf.next_leaf;
                    int j;

                    for (j = 1; tmp != NULL && tmp != cl; j++) {
                        tmp = tmp->leaf.next_leaf;
                    }

                    if (cycle_size == -1) {
                        cycle_size = j;
                    } else if (cycle_size != j) {
                        printk(KERN_ERR "Verification failed at line %d for %u", __LINE__, classid(cl));
                        return false;
                    }
                }
            } else {
                if (is_active_inner(cl) && !is_attached_inner(cl)) {
                    printk(KERN_ERR "Verification failed at line %d for %u", __LINE__, classid(cl));
                    return false;
                }
                if (is_active_inner(cl) && (cl->inner.first_leaf == NULL || cl->inner.last_leaf == NULL)) {
                    printk(KERN_ERR "Verification failed at line %d for %u", __LINE__, classid(cl));
                    return false;
                }
            }
		}
	}

    if (q->root->inner.first_leaf != NULL) {
        for (cl = q->root->inner.first_leaf; true; cl = cl->leaf.next_leaf) {
            for(ancestor = cl->parent; ancestor != q->root; ancestor = ancestor->parent) {
                if (ancestor == NULL) {
                    printk(KERN_ERR "Verification failed at line %d for %u", __LINE__, classid(cl));
                    return false;
                }
                if (classid(ancestor) < 20) {
                    if (!reached[classid(ancestor)] && ancestor->inner.first_leaf != cl) {
                        printk(KERN_ERR "Verification failed at line %d for %u ancestor %u", __LINE__, classid(cl), classid(ancestor));
                        return false;
                    }
                    reached[classid(ancestor)] = true;

                    if (past[classid(ancestor)]) {
                        printk(KERN_ERR "Verification failed at line %d for %u ancestor %u", __LINE__, classid(cl), classid(ancestor));
                        return false;
                    } else if (ancestor->inner.last_leaf == cl) {
                        past[classid(ancestor)] = true;
                    }
                }
            }
            

            if (cl == q->root->inner.last_leaf) {
                break;
            }
        }
    }

    //printk(KERN_DEBUG "Verification succeed");
    return true;
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

