# Commercial hypothesis — unvalidated, 22 October 2026

Potential customer: a small engineering team shipping customer-facing AI integrations, with several MCP clients/configs and a designated technical owner. The operational problem is keeping inventory, approved permissions and remediation evidence consistent across developers, CI and deployed runtimes.

Evidence: [CERT-In's 15 October advisory](https://www.cert-in.org.in/s2cMainServlet?CACODE=CICA-2026-3630&pageid=PUBADV01) reports unauthorized access missed by affected organizations. [ENISA's PHP statement](https://www.enisa.europa.eu/news/joint-statement-on-critical-php-vulnerabilities) calls for inventory/vendor coordination. These support the existence of operational security gaps, not purchasing demand for MCPSense or a specific market size.

Alternatives include Snyk Agent Scan, Cisco MCP Scanner, Microsoft's governance toolkit, existing SCA/config scanners, manual reviews and internal scripts; see the [research comparison](2026-10-security-landscape.md). MCPSense could offer a small MIT local workflow with reproducible before/after evidence and explicit incomplete coverage. That differentiation is an inference and is currently undermined by the defects in the audit.

Unvalidated: recurrence of the problem for this customer segment, severity of costs, frequency of reviews, preferred evidence formats, access/privacy constraints, willingness to pay and superiority to existing tools. No interviews, pilots, contracts or revenue were obtained.

Proposed service-led pilot: after P0 fixes, perform one explicitly authorized local review for each of five teams. Agree scan scope, record a privacy-safe baseline, help the team remediate a small set of confirmed findings, repeat checks, and ask whether the evidence changed an engineering or customer decision. Keep essential scanner features MIT; no hosted service required.

Ask five prospective users:

1. Show the last integration change you approved: who inventoried it and what evidence was retained?
2. What did the last security remediation cost in engineer hours, and how was closure verified?
3. Which failures or false alerts made you stop trusting existing scanners?
4. What information may leave your machine, and what local/CI outputs are actually required?
5. Would you repeat this review next month, who owns it, and what existing budget/process would fund help?

Before building hosted software, require repeated real use, measurable time saved, accepted evidence formats, a named owner, privacy requirements and genuine paid-pilot or procurement evidence. Stop or narrow the hypothesis if reviews are rare, existing tools suffice, findings do not change decisions, or teams will neither maintain baselines nor fund assistance. Hypothetical pricing is not revenue.
