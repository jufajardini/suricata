***********
JsonBuilder
***********

.. contents:: Table of Contents

Overview
========

JsonBuilder is Suricata's tool for generating JSON logs in Extensible Event Format (EVE, in short). It aims at
performance, since it is used by the main logger functionality in Suricata (the eve.json logs), to register output of several different types of events - alerts, application layer protocols, anomalies - in a short period of time.

It is writen in Rust, but also available for usage in C.

Function Calls
==============

Types
=====

Examples
========
