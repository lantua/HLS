# Hierarchical Link Sharing

Hierarchical Link Sharing (HLS) is a classful qdisc that implements fair bandwidth allocation over a hierarchy of classes.
Classes with a common parent class receive bandwidth proportional to their weights.

HLS does not contain any shaping mechanism and transmits packets whenever possible.
To add shaping, consider using HLS in tandem with other shapers, such as _netem_ or _tbf_.

In HLS, each class is assigned a positive integer *weight*.
The weight of each class represents the number of bytes that it can transmit relative to its sibling classes.
Classes with large weights are allowed to transmit more data compared to classes with smaller weights if they share the same parent in the hierarchy.

The analysis and details of HLS can be found in *[in proceeding]*. **Note that the current implementation of HLS does not include the surplus round. Every round still recomputes the fair quota of the root class.**

# Installation

TODO

# Classification

Each HLS qdisc contains many (HLS) classes.
Each class has one parent, except for the root class, which has the HLS qdisc as the parent.
Each leaf class contains another qdisc.
The default qdisc is _tc-pfifo_.
When enqueuing a packet, HLS consults the filters attached to the root class:

-  If the filter sends the packet to a leaf class, assign the packet to that leaf class, and the classification finishes,
-  If the filter sends the packet to an internal class, further consult the filters attach to that internal class,
-  If the filter fails, and a valid *default_class* is assigned to the qdisc, assign the packet to *default_class*,
-  Otherwise, drop the packet.

# Link Sharing Algorithm

HLS operates in rounds.
In each round, HLS computes the number of bytes that each class can transmit, called its *quota*.
HLS ensures that the quotas of sibling classes are proportional to their weights.
For example, if classes `i` and `j` are siblings, with class `i` having double the weight of class `j`, when both classes are backlogged, HLS allocates double the quota to class `i` compared to class `j`.

The total weights of all non-root active classes (classes that are backlogged at the beginning of the round) and the total maximum packet sizes of active leaf classes determine the amount of quota allocated to each class, which dictates the round size.

# Usage

TODO

## Qdisc Commands

The root of HLS tree is the qdisc, which has the following parameters:

### parent major:minor | root

A mandatory parameter that indicates the parent qdisc or class. This must be either a valid class handle or *root*.

### handle major:

The handle of the qdisc, which is the major number followed by a colon. It is recommended (but not mandatory) as the classes identifies its qdisc using major number.

### max_len bytes

The default value of *max_len* for classes that does not define its own *max_len* (see below). Defaulted to MTU.

### default_class minor

The minor number of the default class.
Packets that fails to be classified by filters are assigned to this class.
If not assigned, unclassified packets are dropped.

## Class

Aside from the qdisc at the root of the HLS tree, other nodes are classes.
Each class has the following parameters:

### parent major:minor

A mandatory parameter that indicates the parent class. The major number matches the handle of the qdisc.
If this class is the root class, set the minor number to zero or omit the minor number.

### classid major:minor

The major number is the handle of the qdisc. The minor number is the classid of this class. This parameter is mandatory.

### weight weight

The weight of this class. This value must be positive integer. If this class is the root class, its weight may also be zero. Classes with the same parent are transmitted with the bandwidth proportion to their weights.
This parameter is mandatory.

### max_len bytes

The maximum size of the packet that is allowed on this class.
This value must be a positive integer.
Packets larger than *max_len* are dropped. Defaulted to *max_len* of the qdisc.
This value is not used by internal classes.
