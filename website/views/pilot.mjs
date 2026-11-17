const demoVersion = '0.5.1';

export const pilotChannels = ['x', 'linkedin', 'partner', 'outreach'];

const samples = [
  { protocol: 'http', result: 'One high finding (SEC-016), exit 1.' },
  { protocol: 'https', result: 'Zero findings in the config scan, exit 0.' },
];

export const pilotSamples = samples.map(({ protocol }) => ({
  file: `sample-${protocol}.json`,
  contents: JSON.stringify({ mcpServers: { sample: { url: `${protocol}://example.invalid/mcp` } } }, null, 2) + '\n',
}));

export function pilotView({ command, product }) {
  const scan = filename => command(
    `npx --yes --ignore-scripts --package=mcpsense@${demoVersion} -- mcpsense scan ./${filename} --mode config --offline --no-baseline`,
    `Copy scan command for ${filename}`,
  );
  return `<div class="container docs-layout">
    <aside class="docs-sidebar"><a href="#sample">Scan the sample</a><a href="#your-review">Try a pull request</a></aside>
    <article class="docs-content prose">
      <h1>Try an MCP config review</h1>
      <p class="lead">Run an offline scan on two sample files and see what changes when an MCP endpoint switches from HTTP to HTTPS.</p>
      <section id="sample">
        <h2>Run the sample locally</h2>
        <p>Use Node.js 22+ and npm. Save both files in an empty folder and open a terminal there. The first command downloads MCPSense ${demoVersion} through npm. The scan reads the local example file without contacting its endpoint.</p>
        ${samples.map(({ protocol, result }) => {
          const filename = `sample-${protocol}.json`;
          return `<p><a href="/pilot/${filename}" download>Download ${filename}</a></p>
            ${scan(filename)}<p>Expected result: ${result}</p>`;
        }).join('\n')}
        <p>Check the coverage with the finding count. Authentication, tool responses and server behavior require separate review.</p>
      </section>
      <section id="your-review">
        <h2>Use the check on one pull request</h2>
        <p><a href="/docs/#pull-request-review">Copy the workflow and see a completed GitHub Actions run</a>. Start with a config your team already reviews. The report gives reviewers a finding count and leaves the decision to them.</p>
        <p><a href="${product.github}/issues/42">Request a free 20-minute first run or tell us how yours went</a>. If you share feedback, say where you found the pilot and whether you ran the sample, your own config, or a second change. Keep private configs and reports in your own environment.</p>
      </section>
    </article>
  </div>`;
}
