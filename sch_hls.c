/*
 * net/sched/sch_hls.c
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/pkt_sched.h>
#include <net/sch_generic.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

struct tc_hls_opt {
    __u32 weight;
};
struct tc_hls_xstats {
    __u32 deactivate_count;
    __u32 mark_idle_count;
};
enum {
	TCA_HLS_UNSPEC,
	TCA_HLS_PARMS,
    TCA_HLS_MAX_PACKET_SIZE,
	__TCA_HLS_MAX,
};
#define TCA_HLS_MAX (__TCA_HLS_MAX - 1)

typedef u16 Round;

struct hls_class {
	struct Qdisc_class_common	common;
	unsigned int			filter_cnt;

	struct gnet_stats_basic_packed		bstats;
	struct gnet_stats_queue		qstats;
	struct net_rate_estimator __rcu *rate_est;

	struct tcf_proto __rcu  *filter_list;	/* class attached filters */
	struct tcf_block        *block;

    struct hls_class* parent;
    u32 weight, children_count;
    int quota;
    u32 max_packet_size;

    union {
        struct {
            u32 fairshare;
            u32 busy_children_weight;
            Round round;
        } inner;
        struct {
            struct list_head busy_list;
	        struct Qdisc *qdisc;
        } leaf;
    };
};

struct hls_sched {
	struct tcf_proto __rcu  *filter_list;
	struct tcf_block        *block;
	struct Qdisc_class_hash clhash;

    struct list_head busy_leaves;
    struct list_head round_marker;
    struct hls_class *root;
    Round round;
    u32 default_max_packet_size;
};

static bool hls_is_leaf(struct hls_class* cl) { return cl->children_count == 0; }
static bool hls_is_busy_leaf(struct hls_class* cl) { return cl->leaf.qdisc->q.qlen; }
static bool hls_is_busy_inner(struct hls_class* cl) { return cl->inner.busy_children_weight != 0; }

static inline struct hls_class *hls_find(u32 handle, struct Qdisc *sch) {
	struct hls_sched *q = qdisc_priv(sch);
	struct Qdisc_class_common *clc;

	clc = qdisc_class_find(&q->clhash, handle);
	if (clc == NULL)
		return NULL;

	return container_of(clc, struct hls_class, common);
}

static void hls_compute_fairshare(struct hls_class* cl) {
    if (cl->quota <= 0) {
        // No quota, no share.
        cl->inner.fairshare = 0;
    } else {
        // Pretty much any rounding will suffice, but sum-of-quota must be adjusted appropriately.
        cl->inner.fairshare = cl->quota / cl->inner.busy_children_weight;
    }
}

static void hls_take_quota(struct hls_class* cl, u32 share) {
    u32 value = share * cl->weight;
    cl->quota += value;
    cl->parent->quota -= value;
}

static u32 hls_current_inner_fairshare(struct hls_class* cl, Round round) {
    struct hls_class *parent = cl->parent;

    if (cl->inner.round == round) {
        // Cached.
        return cl->inner.fairshare;
    }

    if (parent != NULL) {
        // Take from parent first.
        hls_take_quota(cl, hls_current_inner_fairshare(parent, round));
    }

    cl->inner.round = round;
    hls_compute_fairshare(cl);
    return cl->inner.fairshare;
}

static void hls_update_leaf_quota(struct hls_class* cl, Round round) {
    struct hls_class *parent = cl->parent;

    if (unlikely(parent != NULL)) {
        // Take from parent.
        hls_take_quota(cl, hls_current_inner_fairshare(parent, round));
    }
}

static void hls_advance_leaf(struct hls_sched *q, struct hls_class *cl) {
    list_move_tail(&cl->leaf.busy_list, &q->busy_leaves);

    // If the next item (now *first*) is not a round marker, update its quota.
    if (&q->round_marker != q->busy_leaves.next) {
        hls_update_leaf_quota(list_first_entry(&q->busy_leaves, struct hls_class, leaf.busy_list), q->round);
    }
}

static void hls_advance_round(struct hls_sched *q) {
    q->round += 1;

    list_move_tail(&q->round_marker, &q->busy_leaves);

    // If the next item (now *first*) is not a round marker, update its quota.
    if (likely(&q->round_marker != q->busy_leaves.next)) {
        hls_update_leaf_quota(list_first_entry(&q->busy_leaves, struct hls_class, leaf.busy_list), q->round);
    }
}

static void hls_will_add_busy_child_inner(struct hls_class* cl, Round round) {
    struct hls_class* parent = cl->parent;

    if (hls_is_busy_inner(cl)) {
        // `busy_children_weight` is about to change, but our semantic dictates that `fairshare`
        // depends on `busy_children_weight` at the beginning of the round. So we compute `fairshare`
        // before we lost the correct value.
        hls_compute_fairshare(cl);
        return;
    }

    // `cl` is getting the first children. Tell its parent too.
    if (parent != NULL) {
        hls_will_add_busy_child_inner(parent, round);
        parent->inner.busy_children_weight += cl->weight; // Add busy child.
    }

    // `cl` just becomes busy, we want it be in the next round. All leaves are
    // behind `round_marker`, so its fairshare will be updated in the next
    // round. We don't want `round` to accidentally points to next round, so 
    // we set it again here.
    cl->inner.round = round;
}

static void hls_did_become_busy_leaf(struct hls_class* cl, struct hls_sched *q) {
    struct hls_class* parent = cl->parent;
    Round round = q->round;

    if (parent != NULL) {
        hls_will_add_busy_child_inner(parent, round);
        parent->inner.busy_children_weight += cl->weight; // Add busy child.
    }

    // Add to busy list, this will always be behind round_marker.
    list_add_tail(&cl->leaf.busy_list, &q->busy_leaves);
    q->root->quota += cl->max_packet_size;    
}

static void hls_did_become_idle_inner(struct hls_class* cl) {
    struct hls_class *parent = cl->parent;

    if (parent != NULL) {
        // Donate quota
        parent->quota += cl->quota;
        cl->quota = 0;

        // Remove busy child
        parent->inner.busy_children_weight -= cl->weight;
        if (!hls_is_busy_inner(parent)) {
            hls_did_become_idle_inner(parent);
        }
    }

    cl->inner.fairshare = 0;
}

static void hls_did_become_idle_leaf(struct hls_class* cl, struct hls_sched* q) {
    struct hls_class *parent = cl->parent;

    if (parent != NULL) {
        // Donate quota
        parent->quota += cl->quota;
        cl->quota = 0;

        // Remove busy child
        parent->inner.busy_children_weight -= cl->weight;
        if (!hls_is_busy_inner(parent)) {
            hls_did_become_idle_inner(parent);
        }
    }

    if (&cl->leaf.busy_list == q->busy_leaves.next) {
        // The "current" class becomes idle, let's say that it finishes its turn.
        hls_advance_leaf(q, cl);
    }

    // Remove from busy list.
    list_del(&cl->leaf.busy_list);
    q->root->quota -= cl->max_packet_size;
}

static struct hls_class *hls_find_class(struct Qdisc *sch, u32 classid)
{
	struct hls_sched *q = qdisc_priv(sch);
	struct Qdisc_class_common *clc;

	clc = qdisc_class_find(&q->clhash, classid);
	if (clc == NULL)
		return NULL;
	return container_of(clc, struct hls_class, common);
}

static void hls_purge_queue(struct hls_class *cl)
{
	unsigned int len = cl->leaf.qdisc->q.qlen;
	unsigned int backlog = cl->leaf.qdisc->qstats.backlog;

	qdisc_reset(cl->leaf.qdisc);
	qdisc_tree_reduce_backlog(cl->leaf.qdisc, len, backlog);
}

static const struct nla_policy hls_policy[TCA_HLS_MAX + 1] = {
    [TCA_HLS_PARMS] = { .len = sizeof(struct tc_hls_opt) },
    [TCA_HLS_MAX_PACKET_SIZE] = { .len = sizeof(__u32) },
};

/// Child must be deactivated
static void hls_attach_child(struct hls_class *child, struct hls_class *parent, struct hls_sched* q) {
    if (unlikely(parent == NULL))
        return;

    if (parent->children_count == 0) {
        // `parent` is leaf, change to inner.
        if (hls_is_busy_leaf(parent)) {
            hls_purge_queue(parent);
            hls_did_become_idle_leaf(parent, q);
        }
        qdisc_destroy(parent->leaf.qdisc);

        memset(&parent->inner, 0, sizeof(parent->inner));
    }
    parent->children_count += 1;
    child->parent = parent;
}

/// Child must be deactivated
static void hls_detach_child(struct hls_class *child, struct Qdisc *sch) {
    struct hls_class *parent = child->parent;

    if (unlikely(parent == NULL))
        return;
    
    parent->children_count -= 1;
    if (parent->children_count == 0) {
        // Last child, change parent to leaf.
        memset(&parent->leaf, 0, sizeof(parent->leaf));
	    parent->leaf.qdisc = qdisc_create_dflt(sch->dev_queue, &pfifo_qdisc_ops, parent->common.classid);
    }
}

static int hls_change_class(struct Qdisc *sch, u32 classid, u32 parentid,
			    struct nlattr **tca, unsigned long *arg)
{
	struct hls_sched *q = qdisc_priv(sch);
	struct hls_class *cl = (struct hls_class *)*arg;
    struct hls_class *parent;
	struct nlattr *opt = tca[TCA_OPTIONS];
	struct nlattr *tb[TCA_HLS_MAX + 1];
    struct tc_hls_opt *hopt;
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_HLS_MAX, opt, hls_policy, NULL);
	if (err < 0)
		return err;

    err = -EINVAL;
    if (tb[TCA_HLS_PARMS] == NULL) {
        return err;
    }
    hopt = nla_data(tb[TCA_HLS_PARMS]);

    parent = parentid == TC_H_ROOT ? NULL : hls_find(parentid, sch);

	if (cl != NULL) {
        if (!hls_is_leaf(cl)) {
            // You can change only leaf classes.
            return -EINVAL;
        }

		if (tca[TCA_RATE]) {
			err = gen_replace_estimator(&cl->bstats, NULL,
						    &cl->rate_est,
						    NULL,
						    qdisc_root_sleeping_running(sch),
						    tca[TCA_RATE]);
			if (err)
				return err;
		}

		sch_tree_lock(sch);
        hls_detach_child(cl, sch);

        q->root->quota -= cl->weight;
        cl->weight = hopt->weight;
        if (tb[TCA_HLS_MAX_PACKET_SIZE]) {
            cl->max_packet_size = *(__u32*)nla_data(tb[TCA_HLS_MAX_PACKET_SIZE]);
        } else {
            cl->max_packet_size = q->default_max_packet_size;
        }
        q->root->quota += cl->weight;

        hls_attach_child(cl, parent, q);
		sch_tree_unlock(sch);

		return 0;
	}

	cl = kzalloc(sizeof(struct hls_class), GFP_KERNEL);
	if (cl == NULL)
		return -ENOBUFS;

    err = tcf_block_get(&cl->block, &cl->filter_list, sch);
    if (err) {
        kfree(cl);
        return err;
    }

	cl->common.classid = classid;
    cl->weight = hopt->weight;
    if (tb[TCA_HLS_MAX_PACKET_SIZE]) {
        cl->max_packet_size = *(__u32*)nla_data(tb[TCA_HLS_MAX_PACKET_SIZE]);
    } else {
        cl->max_packet_size = q->default_max_packet_size;
    }
	cl->leaf.qdisc	   = qdisc_create_dflt(sch->dev_queue,
					       &pfifo_qdisc_ops, classid);
	if (cl->leaf.qdisc == NULL)
		cl->leaf.qdisc = &noop_qdisc;
	else
		qdisc_hash_add(cl->leaf.qdisc, true);

	if (tca[TCA_RATE]) {
		err = gen_replace_estimator(&cl->bstats, NULL, &cl->rate_est,
					    NULL,
					    qdisc_root_sleeping_running(sch),
					    tca[TCA_RATE]);
		if (err) {
			qdisc_destroy(cl->leaf.qdisc);
			kfree(cl);
			return err;
		}
	}

	sch_tree_lock(sch);
	qdisc_class_hash_insert(&q->clhash, &cl->common);
    hls_attach_child(cl, parent, q);

    if (parent == NULL) {
        q->root = cl;
    }
    q->root->quota += hopt->weight;
	sch_tree_unlock(sch);

	qdisc_class_hash_grow(sch, &q->clhash);

	*arg = (unsigned long)cl;
	return 0;
}

static void hls_destroy_class(struct Qdisc *sch, struct hls_class *cl)
{
	gen_kill_estimator(&cl->rate_est);
    tcf_block_put(cl->block);
    if (hls_is_leaf(cl)) {
	    qdisc_destroy(cl->leaf.qdisc);
    }
	kfree(cl);
}

static int hls_delete_class(struct Qdisc *sch, unsigned long arg)
{
	struct hls_sched *q = qdisc_priv(sch);
	struct hls_class *cl = (struct hls_class *)arg;

    if (!hls_is_leaf(cl))
        return -EINVAL;
    if (cl->filter_cnt > 0)
		return -EBUSY;

	sch_tree_lock(sch);

    if (hls_is_busy_leaf(cl)) {
        hls_purge_queue(cl);
        hls_did_become_idle_leaf(cl, q);
    }
    hls_detach_child(cl, sch);
	qdisc_class_hash_remove(&q->clhash, &cl->common);


	sch_tree_unlock(sch);

	hls_destroy_class(sch, cl);
	return 0;
}

static unsigned long hls_search_class(struct Qdisc *sch, u32 classid)
{
	return (unsigned long)hls_find_class(sch, classid);
}

static struct tcf_block *hls_tcf_block(struct Qdisc *sch, unsigned long arg)
{
	struct hls_sched *q = qdisc_priv(sch);
    struct hls_class *cl = (struct hls_class *)arg;

	if (cl)
		return cl->block;

	return q->block;
}

static unsigned long hls_bind_tcf(struct Qdisc *sch, unsigned long parent,
				  u32 classid)
{
	struct hls_class *cl = hls_find_class(sch, classid);

	if (cl != NULL)
		cl->filter_cnt++;

	return (unsigned long)cl;
}

static void hls_unbind_tcf(struct Qdisc *sch, unsigned long arg)
{
	struct hls_class *cl = (struct hls_class *)arg;

	cl->filter_cnt--;
}

static int hls_graft_class(struct Qdisc *sch, unsigned long arg,
			   struct Qdisc *new, struct Qdisc **old)
{
	struct hls_class *cl = (struct hls_class *)arg;

	if (new == NULL) {
		new = qdisc_create_dflt(sch->dev_queue,
					&pfifo_qdisc_ops, cl->common.classid);
		if (new == NULL)
			new = &noop_qdisc;
	}

	*old = qdisc_replace(sch, new, &cl->leaf.qdisc);
	return 0;
}

static struct Qdisc *hls_class_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct hls_class *cl = (struct hls_class *)arg;

    if (hls_is_leaf(cl))
        return cl->leaf.qdisc;

    return NULL;
}

static void hls_qlen_notify(struct Qdisc *sch, unsigned long arg)
{
    struct hls_sched *q = qdisc_priv(sch);
	struct hls_class *cl = (struct hls_class *)arg;

    if (hls_is_busy_leaf(cl))
        hls_did_become_idle_leaf(cl, q);
}

static int hls_dump_class(struct Qdisc *sch, unsigned long arg,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	struct hls_class *cl = (struct hls_class *)arg;
	struct nlattr *nest;

	tcm->tcm_parent	= TC_H_ROOT;
	tcm->tcm_handle	= cl->common.classid;
	tcm->tcm_info	= cl->leaf.qdisc->handle;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;
	//if (nla_put_u32(skb, TCA_HLS_QUANTUM, cl->quantum)) goto nla_put_failure;
	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -EMSGSIZE;
}

static int hls_dump_class_stats(struct Qdisc *sch, unsigned long arg,
				struct gnet_dump *d)
{
    /*
	struct hls_class *cl = (struct hls_class *)arg;
	__u32 qlen = cl->leaf.qdisc->q.qlen;
	struct tc_hls_stats xstats;

	memset(&xstats, 0, sizeof(xstats));
	if (qlen)
		xstats.deficit = cl->deficit;

	if (gnet_stats_copy_basic(qdisc_root_sleeping_running(sch),
				  d, NULL, &cl->bstats) < 0 ||
	    gnet_stats_copy_rate_est(d, &cl->rate_est) < 0 ||
	    gnet_stats_copy_queue(d, NULL, &cl->leaf.qdisc->qstats, qlen) < 0)
		return -1;

	return gnet_stats_copy_app(d, &xstats, sizeof(xstats));
    */
    return -1;
}

static void hls_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct hls_sched *q = qdisc_priv(sch);
	struct hls_class *cl;
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

static struct hls_class *hls_classify(struct sk_buff *skb, struct Qdisc *sch,
				      int *qerr)
{
	struct hls_sched *q = qdisc_priv(sch);
	struct hls_class *cl;
	struct tcf_result res;
	struct tcf_proto *fl = NULL;
    int result;

	if (TC_H_MAJ(skb->priority ^ sch->handle) == 0) {
		cl = hls_find_class(sch, skb->priority);
        if (cl != NULL) {
		    if (hls_is_leaf(cl))
                return cl;

            fl = rcu_dereference_bh(cl->filter_list);
        }
	}

    // If we don't have class filter to start with, use qdisc filter.
    if (fl == NULL) 
	    fl = rcu_dereference_bh(q->filter_list);

	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;

    while (fl && (result = tcf_classify(skb, fl, &res, false)) >= 0) {
#ifdef CONFIG_NET_CLS_ACT
		switch (result) {
		case TC_ACT_QUEUED:
		case TC_ACT_STOLEN:
		case TC_ACT_TRAP:
			*qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
			/* fall through */
		case TC_ACT_SHOT:
			return NULL;
		}
#endif
		cl = (struct hls_class *)res.class;
		if (cl == NULL) {
			cl = hls_find_class(sch, res.classid);
            if (!cl) {
                // Invalid class
                break;
            }
        }

        if (hls_is_leaf(cl))
            return cl;

        // Internal class, retrieve new filter chain.
        fl = rcu_dereference_bh(cl->filter_list);
    }

    // No appropriate class found
	return NULL;
}

static int hls_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		       struct sk_buff **to_free)
{
	struct hls_sched *q = qdisc_priv(sch);
	struct hls_class *cl;
	int err = 0;

	cl = hls_classify(skb, sch, &err);
	if (cl == NULL) {
		if (err & __NET_XMIT_BYPASS)
			qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		return err;
	}

	err = qdisc_enqueue(skb, cl->leaf.qdisc, to_free);
	if (unlikely(err != NET_XMIT_SUCCESS)) {
		if (net_xmit_drop_count(err)) {
			cl->qstats.drops++;
			qdisc_qstats_drop(sch);
		}
		return err;
	}

	if (cl->leaf.qdisc->q.qlen == 1) {
        hls_did_become_busy_leaf(cl, q);
	}

	qdisc_qstats_backlog_inc(sch, skb);
	sch->q.qlen++;
	return err;
}

static struct sk_buff *hls_dequeue(struct Qdisc *sch)
{
	struct hls_sched *q = qdisc_priv(sch);
	struct hls_class *cl;
	struct sk_buff *skb;
	unsigned int len;

    // The list always contains round marker. If that's the only item, we have nothing to send.
	if (list_is_singular(&q->busy_leaves))
		goto out;

    while (1) {
        if (&q->round_marker == q->busy_leaves.next) {
            hls_advance_round(q);
        }

        cl = list_first_entry(&q->busy_leaves, struct hls_class, leaf.busy_list);
        skb = cl->leaf.qdisc->ops->peek(cl->leaf.qdisc);
		if (skb == NULL) {
			qdisc_warn_nonwc(__func__, cl->leaf.qdisc);
			goto out;
		}

        len = qdisc_pkt_len(skb);
        if (len <= cl->quota) {
            cl->quota -= len;
            q->root->quota += len;
			skb = qdisc_dequeue_peeked(cl->leaf.qdisc);
			if (unlikely(skb == NULL))
				goto out;
			if (cl->leaf.qdisc->q.qlen == 0) {
                hls_did_become_idle_leaf(cl, q);
            }

            bstats_update(&cl->bstats, skb);
            qdisc_bstats_update(sch, skb);
            qdisc_qstats_backlog_dec(sch, skb);
            sch->q.qlen--;
            return skb;
        }

        hls_advance_leaf(q, cl);
    }

out:
	return NULL;
}

static int hls_init_qdisc(struct Qdisc *sch, struct nlattr *opt)
{
	struct hls_sched *q = qdisc_priv(sch);
    struct nlattr *tb[TCA_HLS_MAX + 1];
	int err;

    err = nla_parse_nested(tb, TCA_HLS_MAX, opt, hls_policy, NULL);
    if (err < 0)
        return err;

    if (tb[TCA_HLS_MAX_PACKET_SIZE] == NULL)
        return -EINVAL;

    err = tcf_block_get(&q->block, &q->filter_list, sch);
	if (err)
		return err;
	err = qdisc_class_hash_init(&q->clhash);
	if (err < 0)
		return err;
    INIT_LIST_HEAD(&q->busy_leaves);
    list_add_tail(&q->round_marker, &q->busy_leaves);
    q->root = NULL;
    q->default_max_packet_size = *(__u32*)nla_data(tb[TCA_HLS_MAX_PACKET_SIZE]);

    return 0;
}

static void hls_reset_qdisc(struct Qdisc *sch)
{
	struct hls_sched *q = qdisc_priv(sch);
	struct hls_class *cl;
	unsigned int i;

	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry(cl, &q->clhash.hash[i], common.hnode) {
            if (hls_is_leaf(cl)) {
			    qdisc_reset(cl->leaf.qdisc);
			    if (hls_is_busy_leaf(cl)) {
                    hls_did_become_idle_leaf(cl, q);
                }
            }
		}
	}

	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry(cl, &q->clhash.hash[i], common.hnode) {
            if (!hls_is_leaf(cl)) {
                memset(&cl->inner, 0, sizeof(cl->inner));
            }
		}
	}

	sch->qstats.backlog = 0;
	sch->q.qlen = 0;
}

static void hls_destroy_qdisc(struct Qdisc *sch)
{
	struct hls_sched *q = qdisc_priv(sch);
	struct hls_class *cl;
	struct hlist_node *next;
	unsigned int i;

	tcf_block_put(q->block);

	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry_safe(cl, next, &q->clhash.hash[i], common.hnode)
			hls_destroy_class(sch, cl);
	}
	qdisc_class_hash_destroy(&q->clhash);
}

static const struct Qdisc_class_ops hls_class_ops = {
	.change		= hls_change_class,
	.delete		= hls_delete_class,
	.find		= hls_search_class,
	.tcf_block	= hls_tcf_block,
	.bind_tcf	= hls_bind_tcf,
	.unbind_tcf	= hls_unbind_tcf,
	.graft		= hls_graft_class,
	.leaf		= hls_class_leaf,
	.qlen_notify	= hls_qlen_notify,
	.dump		= hls_dump_class,
	.dump_stats	= hls_dump_class_stats,
	.walk		= hls_walk,
};

static struct Qdisc_ops hls_qdisc_ops __read_mostly = {
	.cl_ops		= &hls_class_ops,
	.id		= "hls",
	.priv_size	= sizeof(struct hls_sched),
	.enqueue	= hls_enqueue,
	.dequeue	= hls_dequeue,
	.peek		= qdisc_peek_dequeued,
	.init		= hls_init_qdisc,
	.reset		= hls_reset_qdisc,
	.destroy	= hls_destroy_qdisc,
	.owner		= THIS_MODULE,
};

static int __init hls_init(void)
{
	return register_qdisc(&hls_qdisc_ops);
}

static void __exit hls_exit(void)
{
	unregister_qdisc(&hls_qdisc_ops);
}

module_init(hls_init);
module_exit(hls_exit);
MODULE_LICENSE("GPL");

