---
layout: page
title: CVEs
permalink: /cves/
description: Public vulnerability disclosures and exploit research by Ted Thobane.
---

<p class="page-lede">Public vulnerability disclosures and exploit research, with links to canonical records and technical references.</p>

<div class="cve-list">
  <article class="cve-entry" id="cve-2026-85220">
    <div class="cve-entry-head">
      <div><p class="cve-product">Thinkst Canary · Disclosed finding</p><h2>CVE-2026-85220</h2></div>
      <span class="severity">Low · 3.7</span>
    </div>
    <h3>Unauthenticated denial of service in the Redis service</h3>
    <p>When the Redis service was enabled, an unauthenticated remote attacker could trigger excessive resource allocation and deny service to the Canary honeypot. Thinkst credited Teddy Thobane as the finder.</p>
    <div class="cve-links"><a href="https://www.cve.org/CVERecord?id=CVE-2026-85220">CVE record ↗</a><a href="https://canary.tools/security-advisories/tc-2026-01.txt">Vendor advisory ↗</a></div>
  </article>

  <article class="cve-entry" id="cve-2026-85219">
    <div class="cve-entry-head">
      <div><p class="cve-product">OpenCanary · Disclosed finding</p><h2>CVE-2026-85219</h2></div>
      <span class="severity">Low · 3.7</span>
    </div>
    <h3>Memory-exhaustion denial of service in the Redis module</h3>
    <p>The Redis module could retain memory under attacker-controlled protocol conditions, allowing an unauthenticated remote attacker to cause unconstrained memory use and degrade availability. Thinkst credited Teddy Thobane as the finder.</p>
    <div class="cve-links"><a href="https://www.cve.org/CVERecord?id=CVE-2026-85219">CVE record ↗</a><a href="https://github.com/thinkst/opencanary/security/advisories/GHSA-77jg-5rmj-77jx">Vendor advisory ↗</a></div>
  </article>

  <article class="cve-entry" id="cve-2025-46827">
    <div class="cve-entry-head">
      <div><p class="cve-product">Graylog · Disclosed finding</p><h2>CVE-2025-46827</h2></div>
      <span class="severity">High · 8.0</span>
    </div>
    <h3>Session takeover via insufficient HTML sanitization</h3>
    <p>Stored cross-site scripting in event-definition remediation content could expose user session cookies when the required permissions, viewer interaction, and active input conditions were present.</p>
    <div class="cve-links"><a href="https://nvd.nist.gov/vuln/detail/CVE-2025-46827">NVD record ↗</a><a href="https://github.com/Graylog2/graylog2-server/security/advisories/GHSA-76vf-mpmx-777j">Vendor advisory ↗</a></div>
  </article>

  <article class="cve-entry" id="cve-2024-48911">
    <div class="cve-entry-head">
      <div><p class="cve-product">OpenCanary · Disclosed finding</p><h2>CVE-2024-48911</h2></div>
      <span class="severity">High · 7.8</span>
    </div>
    <h3>Local privilege escalation through trusted configuration</h3>
    <p>A privileged OpenCanary service executed commands from configuration stored in a user-controlled location, creating a path for a local user to escalate privileges when the daemon was run as root.</p>
    <div class="cve-links"><a href="https://nvd.nist.gov/vuln/detail/CVE-2024-48911">NVD record ↗</a><a href="https://github.com/thinkst/opencanary/security/advisories/GHSA-pf5v-pqfv-x8jj">Vendor advisory ↗</a></div>
  </article>

  <article class="cve-entry" id="cve-2024-24824">
    <div class="cve-entry-head">
      <div><p class="cve-product">Graylog · Published exploit research</p><h2>CVE-2024-24824</h2></div>
      <span class="severity">High · 8.8</span>
    </div>
    <h3>Arbitrary class loading and instantiation</h3>
    <p>Developed and published a working exploit that turns Graylog’s arbitrary class loading and instantiation primitive into practical code execution.</p>
    <div class="cve-links"><a href="https://nvd.nist.gov/vuln/detail/CVE-2024-24824">NVD record ↗</a><a href="https://github.com/rootkiTED/graylog-cve-2024-24824-exploit">Exploit repository ↗</a></div>
  </article>
</div>
