---
layout: page
title: About
permalink: /about/
description: About Ted and this security research journal.
---

I’m Ted, a security researcher focused on understanding how software fails—and what those failures teach us about building it better.

This is my working notebook for reverse engineering, binary exploitation, and malware research. The write-ups favour reproducible steps, annotated evidence, and the reasoning behind each result.

## Selected research under NDA

Some of my strongest client work cannot be tied to a company or product publicly. These summaries describe the vulnerability class and demonstrated impact without exposing client-identifying details:

* **Linux multithreaded server:** identified a pre-authentication stack buffer overflow and developed an exploit chain demonstrating remote code execution.
* **Router and OpenVPN integration:** discovered a configuration-injection vulnerability which enabled operating-system command execution.
* **Commercial antivirus software:** developed an exploit for a race condition which produced an arbitrary file-write primitive as SYSTEM and local privilege escalation.
* **Windows system service:** identified a batch-request validation flaw which desynchronised requests from their data, then developed the resulting incorrect routine invocation into a write-what-where primitive while bypassing stack-canary protection.

The descriptions intentionally omit client names, product identifiers, versions, affected components, and reproduction details.

You can find the source and accompanying material on [GitHub](https://github.com/rootkiTED).
