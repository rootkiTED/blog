---
layout: page
title: About
permalink: /about/
description: About Ted Thobane, an exploit engineer and reverse engineer.
---

I’m Ted, an exploit engineer and reverse engineer. I’m passionate about the part of security research that begins after a vulnerability is found: turning an initial crash or weak primitive into a reliable exploit that demonstrates the true impact of the bug.

That work demands a close understanding of the software beneath the surface. I reverse engineer unfamiliar targets, study their memory and control flow, develop exploitation primitives, and work through mitigations until I can explain not only why a system fails, but how far that failure can be taken. Vulnerability research is the starting point; exploit engineering is the craft I care about most.

This site is my working notebook for exploit development, reverse engineering, and vulnerability research. The write-ups favour reproducible steps, annotated evidence, and the reasoning behind each result.

## Selected research under NDA

Some of my strongest client work cannot be tied to a company or product publicly. These summaries describe the vulnerability class and demonstrated impact without exposing client-identifying details:

* **Linux multithreaded server:** identified a pre-authentication stack buffer overflow and developed an exploit chain demonstrating remote code execution.
* **Router and OpenVPN integration:** discovered a configuration-injection vulnerability which enabled operating-system command execution.
* **Commercial antivirus software:** developed an exploit for a race condition which produced an arbitrary file-write primitive as SYSTEM and local privilege escalation.
* **Windows system service:** identified a batch-request validation flaw which desynchronised requests from their data, then developed the resulting incorrect routine invocation into a write-what-where primitive while bypassing stack-canary protection.

The descriptions intentionally omit client names, product identifiers, versions, affected components, and reproduction details.

You can find the source and accompanying material on [GitHub](https://github.com/rootkiTED).
