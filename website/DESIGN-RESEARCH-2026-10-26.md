# MCPSense identity research — 26 October 2026

## Brief and comparison

The maintainer rejected the first dark/mint direction as too similar to the old MCPSense site, then the paper/serif inspection-desk direction as too close to Lore. This revision changes the composition, typography, illustration system and motion together. It retains the plain static Cloudflare delivery, complete blog, changelog and accurate product scope.

The following are design observations from live first-party pages and browser inspection, not endorsements of competitors' security claims. Eight security sites were examined; Arcjet, Socket and Invariant also received below-the-fold inspection. Site behavior can vary with loading and consent state.

| Reference | Observed visual / interaction language | Useful principle for MCPSense | Avoid copying |
| --- | --- | --- | --- |
| [Socket](https://socket.dev/) | Plum background, bold type, stacked alert illustration, pixel motifs; product/evidence sections and developer resources below | Make the thing being inspected concrete; keep an obvious developer entry point | Fabricated live alert totals, purple alert-stack composition, broad prevention claims |
| [Arcjet](https://arcjet.com/) | Black canvas, precise type, restrained luminous separators; a numbered sequence connects actions to an unsafe result and policy decisions | Use sequences to explain a security mechanism | Its runtime allow/deny semantics: MCPSense supplies inspection findings, not an enforcement gate |
| [Aikido](https://www.aikido.dev/) | Large sans-serif statement, strong light/dark contrast, compact navigation and product-specific views | Give the product a recognisable shape and a direct next action | Generic centred SaaS hero, unsupported adoption and accuracy statistics |
| [Semgrep](https://semgrep.dev/) | Light surface, green/grey palette, spare developer-facing hierarchy and direct trial/docs routes | Readability and a clear category matter more than security decoration | Mint branding and a sales form as the main action for a free CLI |
| [Wiz](https://www.wiz.io/) | White/blue, left-aligned copy, clear platform story and separate evidence region; graph language in product copy | Explain what connects to what and why context matters | Enterprise-scale claims/logos and a demo-led funnel unrelated to this project |
| [Lakera](https://www.lakera.ai/) | Dark AI-security setting, blue light-column background, strong type and prominent motion/metric strip | Motion can establish a technical category | Heavy ambient spectacle, moving marketing counters and text competing with light effects |
| [Chainguard](https://www.chainguard.dev/) | Dark structured grid, segmented navigation, high-contrast violet actions and dense technical ecosystem | A consistent graphic system can extend across an entire security site | Dotted-grid wallpaper, violet identity and claims of eliminating all risk |
| [Invariant Labs](https://invariantlabs.ai/) | Spare white/purple presentation, geometric trajectory illustration and separate Explorer/Guardrails/MCP Scan product paths | Illustrate the relationship between input, inspection and outcome | Its circle-grid motif, product portfolio and runtime guardrail positioning |

[Lore](https://loredev.co/) was inspected as a separation check: cream canvas, mixed sans/italic serif headline, blue accents and an angled dark explanatory card. Those defining choices are removed from this revision.

## First-principles decision

MCP gives an agent an interface described by third-party text. Text can describe a capability while also asking for authority, disclosure or deceptive behavior. MCPSense helps inspect that interface and reports review signals. Its identity should make the inspection legible, without implying universal detection or runtime blocking.

**Concept: signal inspection.** A wide technical diagram follows advertised metadata through an inspection plane into a finding and an operator review. The hero is a full-width composition rather than another paragraph beside a tilted card. Graphite, neutral white and a controlled orange accent distinguish the site from both earlier directions. Technical sans-serif typography replaces editorial serif type. The blog and changelog inherit the same signal/trace system.

## Motion contract

- A bounded scan sweep highlights a known suspicious span and connects it to its review finding. It is explicitly an illustrative sequence, not a live service or a general-purpose classifier.
- Replay/pause controls let readers examine the sequence. Reduced-motion preference produces a readable static outcome. Essential copy never starts hidden behind a reveal effect.
- A user-controlled metadata comparison makes drift concrete. It depicts review of changed recognized metadata, not authentication or automatic execution prevention.
- No cursor target, pointer trail, random particle field, continuously incrementing attack counter, flashing warning or copied competitor animation.
- Prefer local CSS/SVG and short state transitions to a video/WebGL background. Content remains usable if scripts fail; ordinary links, installation instructions and article reading do not depend on motion.

The motion controls follow [W3C guidance on pausing moving content](https://www.w3.org/WAI/WCAG22/Understanding/pause-stop-hide.html) and [supporting reduced motion](https://www.w3.org/WAI/WCAG22/Understanding/animation-from-interactions.html). These are implementation requirements, not a claim of complete WCAG conformance.

## Preserve and verify

Keep independent npm/Go onboarding; verified stable 0.4.1 versus candidate 0.4.2; live channel agreement with dated fallback; all article and release links; RSS, sitemap and security headers. Recheck phone/desktop layouts, keyboard controls, pause/replay, no-script presentation, public headers and actual Cloudflare output. The earlier exact-byte public audit stopped on robots.txt; inspect the served difference before describing that audit as passed.
