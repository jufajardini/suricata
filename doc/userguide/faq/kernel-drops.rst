============
kernel_drops
============

Are my kernel_drop values too high?
===================================

As a rule of thumb, when seeing what seems like a high number of kernel_drops,
divide that counter by the total kernel_packets, to have an estimate of the
percentage of the traffic that the drops represent:

.. math::

    capture.kernel_packets / capture.kernel_drops = drops_percentage %

A percentage of up to 5% kernel_drops could happen due to many circumstances,
and in general, shouldn't  be of worry per se. We recommend investigating it
against other counters, and taken into account the network traffic profile
during the drops, as well as hardware capabilities, and new extra factors (any
system updates, for instance?) to decide on that.

We are seeing too high kernel_drop counter stats. What could be the cause?
==========================================================================

Without information on your setup, network traffic profile and more, it is very
hard to tell the cause of the drops seen, or even if there is a reason to worry.

When should we worry?
=====================

There can be many reasons in the system as well as Suricata why a temporary
spike in load might cause some drops. In IPS mode, dropped packets are generally
retransmitted, so low drop rates should not lead to data loss.

