---
layout: post
title: "Making the canary go quiet: CVE-2026-85219 and CVE-2026-85220"
date: 2026-09-30 16:20:00 +0200
categories: Vulnerability-Research
excerpt: "From source review to a full unauthenticated denial of service in the Redis service used by OpenCanary and Thinkst Canary."
---

What happens when the thing watching for attackers can be switched off by an attacker?

That question led me into the Redis implementation in OpenCanary and, eventually, to two CVEs:

* [CVE-2026-85219](https://www.cve.org/CVERecord?id=CVE-2026-85219), covering the OpenCanary Redis module; and
* [CVE-2026-85220](https://www.cve.org/CVERecord?id=CVE-2026-85220), covering the Redis service in Thinkst Canary.

The issue was an unauthenticated remote denial of service caused by incomplete Redis requests being buffered without an effective upper bound. In my controlled test environment, memory exhaustion terminated the OpenCanary process in just under four minutes. Because the enabled honeypot services shared that process, the Redis, FTP, MySQL, and other OpenCanary listeners became unavailable together while the legitimate SSH service kept running.

Thinkst coordinated the disclosure, credited me as the finder, and released fixes on 21 September 2026. I held the exploit back for an additional patch window. That window has now passed, so here is the full OpenCanary source analysis and the proof of concept.

The commercial Canary code is not public, so the line-by-line analysis below is limited to OpenCanary 0.9.9. The separate Thinkst Canary CVE and its affected platforms are documented in the vendor advisory.

# What the Redis service is meant to do

OpenCanary is a lightweight network honeypot. It exposes services which look interesting enough for an intruder to touch, then generates high-signal alerts when they do. The Redis module imitates a Redis server on TCP port 6379 by default.

It is not trying to be a production datastore. It only needs to speak enough of the Redis Serialization Protocol, or RESP, to look convincing, parse incoming commands, reject unauthenticated use, and log the interaction.

A normal RESP array containing an `AUTH` command looks roughly like this:

```text
*2\r\n
$4\r\n
AUTH\r\n
$8\r\n
password\r\n
```

The array says that it contains two elements. Each bulk string then declares its own length before the data. TCP may split that request across several packets, so the service cannot assume that one call to `dataReceived()` contains the whole command.

The intended flow is straightforward:

```text
Receive bytes
     |
     v
Append them to the connection buffer
     |
     v
Try to parse a complete RESP command
     |
     +---- complete ----> handle and log it
     |
     +---- incomplete --> wait for more bytes
```

Waiting for more data is normal. The security issue appears when *die hele ding* [the whole thing] can retain an unlimited amount of incomplete data without a boundary.

# Source analysis: where the bug lived

The vulnerable code lived in `opencanary/modules/redis.py`, specifically in the interaction between `_parseRESPString()` and `dataReceived()`.

## The parser trusted the declared length

OpenCanary 0.9.9 parsed a RESP bulk string like this:

```python
def _parseRESPString(cmd_string):
    if cmd_string[0] != "$":
        raise ProtocolError(
            "expected '$', got '{c}'".format(c=cmd_string[0])
        )

    curr_ptr = cmd_string.find("\r\n")
    if curr_ptr == -1:
        raise RedisCommandAgain()

    str_length = cmd_string[1:curr_ptr]
    curr_ptr += 2

    try:
        str_length = int(str_length)
    except ValueError:
        raise ProtocolError("invalid bulk length")

    resp_str = cmd_string[curr_ptr : curr_ptr + str_length + 2]

    if len(resp_str) + 2 < str_length or resp_str[-2:] != "\r\n":
        raise RedisCommandAgain()

    curr_ptr += str_length + 2
    return resp_str[:-2], curr_ptr
```

`str_length` came directly from the remote client. The code verified that it was an integer, but it did not enforce a maximum acceptable length before using it to decide whether the request was complete.

Importantly, declaring a two-gigabyte bulk string did not immediately make Python allocate two gigabytes. It put the parser into a state where it expected that much data before it would consider the element complete.

If the advertised body had not arrived yet, `_parseRESPString()` raised `RedisCommandAgain`. That exception was the parser saying, "Sharp [alright], I need more bytes. Try me again later."

So far, that is still normal protocol handling.

## The receive buffer had no ceiling

The problem became exploitable in `dataReceived()`:

```python
def dataReceived(self, data):
    try:
        try:
            if not hasattr(self, "_data"):
                self._data = data.decode()
            else:
                self._data += data.decode()

            cmds = self._processRedisCommand()

            for cmd, args in cmds:
                self._buildResponseAndSend(cmd, args)

        except RedisCommandAgain:
            pass

    except ProtocolError as e:
        self._errorAndClose(e.message)
```

When the parser requested more data, the exception was caught without clearing the buffered state. The partial request remained in `self._data`, the connection remained open, and the next packet was appended to the same buffer.

There was no effective check on:

* the client-supplied bulk-string length;
* the size of `self._data`;
* the total incomplete request retained by one connection; or
* how long that incomplete state was allowed to live.

A client could therefore advertise a body much larger than it intended to finish, continuously send data below that declared length, and make the process retain the lot.

## The existing limit covered a different stage

The Redis module already had a setting called `redis.max_arg_length`. I initially checked whether that killed the idea. It did not.

```python
def _logAlert(self, cmd, args):
    args = " ".join(args)
    if len(args) > self.factory.max_arg_length:
        args = args[: self.factory.max_arg_length] + ...
```

That setting truncated arguments when an already parsed command was written to the alert log. My request never reached that stage because it was intentionally incomplete.

This is a useful auditing lesson: a size-related setting may be correctly implemented for one purpose without protecting an earlier stage of the data flow. This logging limit was not intended to constrain memory already retained by the protocol parser.

# The first test

The first test was deliberately small. I sent a valid RESP array prefix containing `AUTH`, followed it with a second bulk-string header advertising a very large body, sent only part of that body, and left the connection open.

Conceptually:

```text
*2\r\n
$4\r\n
AUTH\r\n
$<very large length>\r\n
AAAA... but never enough to finish the bulk string
```

The defensive behaviours I was looking for were rejection of an unreasonable length, a receive-buffer limit, an incomplete-request timeout, or connection closure.

In OpenCanary 0.9.9, this particular parsing path instead kept the partial body resident while it waited for the remainder of the declared request. That behaviour gave me the condition I needed to investigate further.

At that point the primitive was confirmed:

```text
attacker-controlled connection
            |
            v
attacker-controlled retained bytes
            |
            v
no effective per-connection upper bound
```

One connection showed the bug. It did not yet demonstrate meaningful denial of service.

# Turning the primitive into a full DoS

The next step was to repeat the incomplete-request pattern across concurrent connections.

Each worker in the proof of concept:

1. opens a TCP connection to the Redis listener;
2. sends the valid RESP prefix and oversized declared length;
3. transmits 16 MiB without completing the bulk string;
4. holds the socket open for 60 seconds; and
5. allows new worker threads to continue applying pressure asynchronously.

The core is intentionally simple:

```python
sock.sendall(build_incomplete_request(declared_size))

remaining = send_bytes
chunk = b"A" * CHUNK_SIZE

while remaining > 0:
    current_chunk_size = min(remaining, CHUNK_SIZE)
    sock.sendall(chunk[:current_chunk_size])
    remaining -= current_chunk_size

time.sleep(hold)
```

The full cleaned proof of concept is available here:

**[Download `opencanaryShutdownExploit.py`]({{ '/assets/exploits/CVE-2026-85219/opencanaryShutdownExploit.py' | relative_url }})**

Use it only in a lab or against a system you are explicitly authorised to test. This is a real denial-of-service exploit, not a version checker.

```bash
python3 opencanaryShutdownExploit.py -p 6379 <authorised-target>
```

# Watching the process fall over

My test target was OpenCanary 0.9.9 running under `twistd` on an Ubuntu Server VM with approximately 6 GB of RAM and eight virtual CPUs. The Redis module was enabled on TCP port 6379.

I recorded the baseline RSS, started the proof of concept, and watched the process:

```bash
watch -n 0.2 'ps -C twistd -o pid,rss,vsz,%mem,cmd'
```

The result was not subtle. RSS climbed continuously as the incomplete requests remained attached to their connections. Some connection attempts eventually timed out, but enough remained active to keep memory consumption moving in one direction: up.

In just under four minutes, the `twistd` process was gone.

I confirmed the result in three ways:

* the monitored process disappeared;
* new connections to the Redis listener were refused; and
* the previously listening OpenCanary ports were no longer present.

That last point mattered. OpenCanary creates one Twisted application and attaches its enabled services to it. The Redis listener was not an isolated worker which could die harmlessly. In my test, exhausting the process through Redis also removed the FTP and MySQL honeypot listeners. The legitimate SSH service, running independently, stayed online.

So the final impact chain was:

```text
Unauthenticated Redis connection
              |
              v
Incomplete RESP request retained
              |
              v
Concurrent unbounded buffers
              |
              v
Process memory exhaustion
              |
              v
OpenCanary and co-hosted listeners terminate
              |
              v
Monitoring blind spot
```

For a security product, that is the important part of the impact. The protected services can remain alive while the monitoring layer quietly disappears. *Yoh* [an expression of surprise].

# About identifying the honeypot

There is a reliable way to determine whether the exposed service or host is behaving like a Canary rather than an ordinary Redis deployment.

I am not publishing it.

The denial-of-service details are now public because fixes are available and defenders can patch. A neat little "yes, *bru* [mate], this is definitely the tripwire" oracle would mostly help attackers decide what to silence before continuing. They do not need that edge gift-wrapped for them. That one stays in the vault. *8ta* [cheers].

# The fix

OpenCanary 0.9.10 substantially hardened the Redis implementation. The relevant controls now include:

* validation of declared RESP lengths;
* a restricted unauthenticated bulk-string length;
* a maximum receive-buffer size;
* a maximum command size;
* idle/incomplete-request timeouts; and
* a configurable connection limit.

These controls address the problem at several levels. That matters: only limiting the declared bulk string would leave other buffer-growth paths to investigate, while only adding a timeout could still permit rapid allocation before expiry.

OpenCanary users should upgrade to 0.9.10 or later. If that cannot happen immediately, disable the Redis module by setting `"redis.enabled": false` and restart OpenCanary. See the [OpenCanary security advisory](https://github.com/thinkst/opencanary/security/advisories/GHSA-77jg-5rmj-77jx).

Thinkst Canary users should ensure that their Canary has received the update for its platform. Automatic updates already have fixes in distribution; systems without automatic updates should be updated manually. Disabling the Redis service is the documented workaround. The [Thinkst Canary advisory](https://canary.tools/security-advisories/tc-2026-01.txt) lists the fixed platform releases.

# Severity and disclosure

The official records assign both CVEs a CVSS 3.1 score of 3.7 (Low): `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L`.

My original assessment was 7.5 (High): `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`. I reached that score because exploitation required no credentials, no user interaction, and no race condition, and because the demonstrated result was complete termination of the shared OpenCanary process and its co-hosted detection services.

The vendor score is the official score. I am recording both because the difference is part of the research, and because deployment context changes how much visibility disappears when that process dies.

Credit to Thinkst for handling the coordinated disclosure and shipping the remediation across OpenCanary and the supported Canary platforms.

This research and proof of concept were developed in a controlled environment and are published for defensive education and authorised security testing only.

Happy Hacking!
