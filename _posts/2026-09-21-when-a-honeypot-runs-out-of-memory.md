---
layout: post
title: "When a honeypot runs out of memory: CVE-2026-85219 and CVE-2026-85220"
date: 2026-09-21 21:39:43 +0200
categories: Vulnerability-Research
excerpt: "How incomplete Redis requests became an unauthenticated denial of service in OpenCanary and Thinkst Canary."
---

A honeypot is supposed to make an attacker's presence visible. If an attacker can remotely switch off that visibility first, the failure is more interesting than an ordinary service crash.

That was the outcome of my research into the Redis emulation used by OpenCanary. A client could keep deliberately incomplete protocol messages alive while the service continued retaining their data. With no effective ceiling on that retained state, memory use grew until the process died.

The coordinated disclosure resulted in two CVEs:

* [CVE-2026-85219](https://www.cve.org/CVERecord?id=CVE-2026-85219) covers the OpenCanary Redis module.
* [CVE-2026-85220](https://www.cve.org/CVERecord?id=CVE-2026-85220) covers the Redis service in Thinkst Canary.

Both issues require the Redis service to be enabled and reachable. Neither requires authentication or user interaction. Thinkst credited me as the finder of both vulnerabilities and has released fixes.

# RESP and the promise of more data

Redis clients and servers communicate using RESP, the Redis Serialization Protocol. A bulk string begins with a declared length followed by the corresponding data. A parser therefore has to handle a perfectly normal network condition: the complete value may not have arrived yet.

The usual response is to retain what has arrived and wait for the rest. That is safe only when the parser also enforces boundaries.

In the affected OpenCanary path, the declared bulk-string length came from the network. When the receive buffer did not yet contain the advertised amount of data, the parser raised an internal signal meaning, effectively, "try again when more bytes arrive."

The receive handler caught that signal and left the partial request in the connection buffer. The next packet was appended to the same buffer before parsing resumed.

Conceptually, the flow looked like this:

```text
Receive data
     |
     v
Append it to the connection buffer
     |
     v
Parse the RESP request
     |
     +---- complete ----> process the command
     |
     +---- incomplete --> retain everything and wait
                              |
                              +---- next packet loops back
```

Retaining an incomplete request is not the vulnerability by itself. The problem was that neither the advertised element length nor the accumulated per-connection buffer had an effective upper bound in this path.

# A limit in the wrong layer

OpenCanary already had a setting named `redis.max_arg_length`. At first glance, that sounds like the control which should stop oversized Redis input.

It did not.

That value limited how much of an already parsed argument was written to an alert log. The vulnerable allocation happened earlier, while the parser was still waiting for the request to become complete. A logging limit cannot protect a receive buffer which grows before logging is reached.

This is a useful review lesson: the existence of a size-related configuration option says nothing about which stage of the data flow it actually constrains. A limit applied after parsing does not bound parser state.

# From one connection to process exhaustion

An incomplete request remained associated with its TCP connection. Keeping several such connections active allowed their retained buffers to grow independently.

During controlled testing against OpenCanary 0.9.9, the resident memory of the shared `twistd` process increased continuously until the process was terminated through memory exhaustion. The attack did not need a valid completed Redis command or an authenticated session.

I am deliberately not publishing the exploit kit, exact request values, connection strategy, or reproduction commands yet. The CVEs and patches are public, but giving operators time to update matters more than releasing a turnkey denial-of-service tool on day one.

# Why this is more than a Redis listener crash

OpenCanary attaches its enabled honeypot modules to one Twisted application. The Redis listener is therefore not necessarily isolated in its own disposable worker.

When memory exhaustion terminates that shared process, the effect can extend to the other OpenCanary listeners hosted alongside Redis. The real services on the machine may continue running while the deception and monitoring layer disappears.

That creates an awkward inversion of the product's purpose:

```text
Reach exposed Redis honeypot
            |
            v
Grow retained parser state
            |
            v
Exhaust the shared process
            |
            v
Other honeypot listeners disappear
            |
            v
Monitoring blind spot
```

The official CVE records assign both findings a CVSS 3.1 score of 3.7 (Low), with high attack complexity and low availability impact. My original OpenCanary report assessed the demonstrated impact more severely because the complete process and its co-hosted detection services could be lost. The published score is the vendor-assigned score; the distinction is worth recording because environmental deployment choices determine how much monitoring disappears with the process.

# Fixing the state machine, not the symptom

A robust protocol service needs limits at the point where it assumes ownership of untrusted data. For this class of bug, the important controls are:

* reject declared RESP elements above a safe maximum before waiting for their bodies;
* cap the total receive buffer retained by each connection;
* close connections which repeatedly fail to complete a request;
* apply a deadline to incomplete protocol state; and
* release the associated buffer when a connection is rejected or expires.

These controls are complementary. A maximum element length does not necessarily constrain aggregate request state, and a timeout alone may still allow rapid memory growth before it fires.

OpenCanary users should upgrade to version 0.9.10 or later. Where an immediate update is not possible, disable the Redis module by setting `"redis.enabled": false` and restart the service. The [OpenCanary advisory](https://github.com/thinkst/opencanary/security/advisories/GHSA-77jg-5rmj-77jx) contains the authoritative open-source remediation information.

Thinkst Canary users should ensure their Canaries have received the vendor update for their platform. Automatic updates already have the fix in distribution; users with automatic updates disabled should update manually. Disabling the Redis service is the documented workaround. The [Thinkst Canary advisory](https://canary.tools/security-advisories/tc-2026-01.txt) lists the first fixed release for each supported platform.

# Disclosure note

The vulnerability details in this post are limited to the root cause, demonstrated impact, and defensive controls needed to understand the failure. The exploit kit remains private for now. I may publish a fuller lab walkthrough after users have had a reasonable patch window, but it will not precede responsible remediation.

This research was performed in a controlled environment and is shared for defensive education and authorised security research only.

Happy Hacking!
