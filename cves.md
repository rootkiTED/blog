---
layout: page
title: CVEs
permalink: /cves/
description: Public vulnerability disclosures and exploit research by Ted Thobane.
---

<p class="page-lede">Public vulnerability disclosures and exploit research, with links to canonical records and technical references.</p>

<div class="cve-list">
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
