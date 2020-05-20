/*
 * net/sched/sch_hls.c
 *
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
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
struct tc_hls_glob {
    __u64 rate;         // limited rate of the link
    __u32 defcls;       // default class number
    __u32 direct_qlen;  // Length of direct queue, in packets
};
struct tc_hls_xstats {
    __u32 deactivate_count;
    __u32 mark_idle_count;
};
enum {
	TCA_HLS_UNSPEC,
	TCA_HLS_PARMS,
	TCA_HLS_INIT,
	__TCA_HLS_MAX,
};
#define TCA_HLS_MAX (__TCA_HLS_MAX - 1)

struct hls_class {
	struct Qdisc_class_common	common;
	unsigned int			filter_cnt;

	struct gnet_stats_basic_packed		bstats;
	struct gnet_stats_queue		qstats;
	struct net_rate_estimator __rcu *rate_est;
	struct list_head		alist;
	struct Qdisc			*qdisc;

	u32				quantum;
	u32				deficit;
};

struct hls_sched {
	struct list_head		active;
	struct tcf_proto __rcu		*filter_list;
	struct tcf_block		*block;
	struct Qdisc_class_hash		clhash;
};

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
	unsigned int len = cl->qdisc->q.qlen;
	unsigned int backlog = cl->qdisc->qstats.backlog;

	qdisc_reset(cl->qdisc);
	qdisc_tree_reduce_backlog(cl->qdisc, len, backlog);
}

static const struct nla_policy hls_policy[TCA_HLS_MAX + 1] = {
    [TCA_HLS_PARMS] = { .len = sizeof(struct tc_hls_opt) },
    [TCA_HLS_INIT] = { .len = sizeof(struct tc_hls_glob) },
};

static int hls_change_class(struct Qdisc *sch, u32 classid, u32 parentid,
			    struct nlattr **tca, unsigned long *arg)
{
	struct hls_sched *q = qdisc_priv(sch);
	struct hls_class *cl = (struct hls_class *)*arg;
	struct nlattr *opt = tca[TCA_OPTIONS];
	struct nlattr *tb[TCA_HLS_MAX + 1];
    struct tc_hls_opt *hopt;
	u32 quantum;
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

    quantum = hopt->weight * 1000;

	if (cl != NULL) {
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
        cl->quantum = quantum;
		sch_tree_unlock(sch);

		return 0;
	}

	cl = kzalloc(sizeof(struct hls_class), GFP_KERNEL);
	if (cl == NULL)
		return -ENOBUFS;

	cl->common.classid = classid;
	cl->quantum	   = quantum;
	cl->qdisc	   = qdisc_create_dflt(sch->dev_queue,
					       &pfifo_qdisc_ops, classid);
	if (cl->qdisc == NULL)
		cl->qdisc = &noop_qdisc;
	else
		qdisc_hash_add(cl->qdisc, true);

	if (tca[TCA_RATE]) {
		err = gen_replace_estimator(&cl->bstats, NULL, &cl->rate_est,
					    NULL,
					    qdisc_root_sleeping_running(sch),
					    tca[TCA_RATE]);
		if (err) {
			qdisc_destroy(cl->qdisc);
			kfree(cl);
			return err;
		}
	}

	sch_tree_lock(sch);
	qdisc_class_hash_insert(&q->clhash, &cl->common);
	sch_tree_unlock(sch);

	qdisc_class_hash_grow(sch, &q->clhash);

	*arg = (unsigned long)cl;
	return 0;
}

static void hls_destroy_class(struct Qdisc *sch, struct hls_class *cl)
{
	gen_kill_estimator(&cl->rate_est);
	qdisc_destroy(cl->qdisc);
	kfree(cl);
}

static int hls_delete_class(struct Qdisc *sch, unsigned long arg)
{
	struct hls_sched *q = qdisc_priv(sch);
	struct hls_class *cl = (struct hls_class *)arg;

	if (cl->filter_cnt > 0)
		return -EBUSY;

	sch_tree_lock(sch);

	hls_purge_queue(cl);
	qdisc_class_hash_remove(&q->clhash, &cl->common);

	sch_tree_unlock(sch);

	hls_destroy_class(sch, cl);
	return 0;
}

static unsigned long hls_search_class(struct Qdisc *sch, u32 classid)
{
	return (unsigned long)hls_find_class(sch, classid);
}

static struct tcf_block *hls_tcf_block(struct Qdisc *sch, unsigned long cl)
{
	struct hls_sched *q = qdisc_priv(sch);

	if (cl)
		return NULL;

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

	*old = qdisc_replace(sch, new, &cl->qdisc);
	return 0;
}

static struct Qdisc *hls_class_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct hls_class *cl = (struct hls_class *)arg;

	return cl->qdisc;
}

static void hls_qlen_notify(struct Qdisc *csh, unsigned long arg)
{
	struct hls_class *cl = (struct hls_class *)arg;

	list_del(&cl->alist);
}

static int hls_dump_class(struct Qdisc *sch, unsigned long arg,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	struct hls_class *cl = (struct hls_class *)arg;
	struct nlattr *nest;

	tcm->tcm_parent	= TC_H_ROOT;
	tcm->tcm_handle	= cl->common.classid;
	tcm->tcm_info	= cl->qdisc->handle;

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
	__u32 qlen = cl->qdisc->q.qlen;
	struct tc_hls_stats xstats;

	memset(&xstats, 0, sizeof(xstats));
	if (qlen)
		xstats.deficit = cl->deficit;

	if (gnet_stats_copy_basic(qdisc_root_sleeping_running(sch),
				  d, NULL, &cl->bstats) < 0 ||
	    gnet_stats_copy_rate_est(d, &cl->rate_est) < 0 ||
	    gnet_stats_copy_queue(d, NULL, &cl->qdisc->qstats, qlen) < 0)
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
	struct tcf_proto *fl;
	int result;

	if (TC_H_MAJ(skb->priority ^ sch->handle) == 0) {
		cl = hls_find_class(sch, skb->priority);
		if (cl != NULL)
			return cl;
	}

	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	fl = rcu_dereference_bh(q->filter_list);
	result = tcf_classify(skb, fl, &res, false);
	if (result >= 0) {
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
		if (cl == NULL)
			cl = hls_find_class(sch, res.classid);
		return cl;
	}
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

	err = qdisc_enqueue(skb, cl->qdisc, to_free);
	if (unlikely(err != NET_XMIT_SUCCESS)) {
		if (net_xmit_drop_count(err)) {
			cl->qstats.drops++;
			qdisc_qstats_drop(sch);
		}
		return err;
	}

	if (cl->qdisc->q.qlen == 1) {
		list_add_tail(&cl->alist, &q->active);
		cl->deficit = cl->quantum;
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

	if (list_empty(&q->active))
		goto out;
	while (1) {
		cl = list_first_entry(&q->active, struct hls_class, alist);
		skb = cl->qdisc->ops->peek(cl->qdisc);
		if (skb == NULL) {
			qdisc_warn_nonwc(__func__, cl->qdisc);
			goto out;
		}

		len = qdisc_pkt_len(skb);
		if (len <= cl->deficit) {
			cl->deficit -= len;
			skb = qdisc_dequeue_peeked(cl->qdisc);
			if (unlikely(skb == NULL))
				goto out;
			if (cl->qdisc->q.qlen == 0)
				list_del(&cl->alist);

			bstats_update(&cl->bstats, skb);
			qdisc_bstats_update(sch, skb);
			qdisc_qstats_backlog_dec(sch, skb);
			sch->q.qlen--;
			return skb;
		}

		cl->deficit += cl->quantum;
		list_move_tail(&cl->alist, &q->active);
	}
out:
	return NULL;
}

static int hls_init_qdisc(struct Qdisc *sch, struct nlattr *opt)
{
	struct hls_sched *q = qdisc_priv(sch);
	int err;

	err = tcf_block_get(&q->block, &q->filter_list, sch);
	if (err)
		return err;
	err = qdisc_class_hash_init(&q->clhash);
	if (err < 0)
		return err;
	INIT_LIST_HEAD(&q->active);
	return 0;
}

static void hls_reset_qdisc(struct Qdisc *sch)
{
	struct hls_sched *q = qdisc_priv(sch);
	struct hls_class *cl;
	unsigned int i;

	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry(cl, &q->clhash.hash[i], common.hnode) {
			if (cl->qdisc->q.qlen)
				list_del(&cl->alist);
			qdisc_reset(cl->qdisc);
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
		hlist_for_each_entry_safe(cl, next, &q->clhash.hash[i],
					  common.hnode)
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
	.id		= "hdrr",
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

