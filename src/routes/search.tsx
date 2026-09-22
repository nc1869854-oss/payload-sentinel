import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Search as SearchIcon } from "lucide-react";

import {
  Cell,
  DataTable,
  Notice,
  PageHeader,
  Panel,
  RiskPill,
  Row,
  SeverityPill,
  Tag,
} from "@/components/console";
import {
  DNS_RECORDS,
  EVIDENCE,
  FINDINGS,
  FLOWS,
  PACKETS,
  formatBytes,
  formatNumber,
} from "@/lib/sample-data";

export const Route = createFileRoute("/search")({
  head: () => ({
    meta: [
      { title: "Search the case — Payload Capture Suite" },
      {
        name: "description",
        content:
          "One search box across packets, conversations, detections, name lookups and evidence, so an address or domain can be traced through the whole case at once.",
      },
      { property: "og:title", content: "Search the case — Payload Capture Suite" },
      {
        property: "og:description",
        content:
          "Cross-reference an address, port, domain or keyword against every record captured in the session.",
      },
    ],
  }),
  component: SearchPage,
});

const SUGGESTIONS = ["203.0.113.47", "445", "hosted-metrics.io", "beacon", "F-001", "TXT"];

function SearchPage() {
  const [query, setQuery] = useState("203.0.113.47");
  const needle = query.trim().toLowerCase();

  const results = useMemo(() => {
    if (!needle) {
      return { packets: [], flows: [], findings: [], dns: [], evidence: [] };
    }
    return {
      packets: PACKETS.filter(
        (packet) =>
          packet.srcIp.includes(needle) ||
          packet.dstIp.includes(needle) ||
          String(packet.srcPort ?? "").includes(needle) ||
          String(packet.dstPort ?? "").includes(needle) ||
          packet.protocol.toLowerCase().includes(needle) ||
          packet.flowId.toLowerCase().includes(needle) ||
          packet.summary.toLowerCase().includes(needle),
      ).slice(0, 40),
      flows: FLOWS.filter(
        (flow) =>
          flow.remoteIp.includes(needle) ||
          flow.remoteHost.toLowerCase().includes(needle) ||
          flow.id.toLowerCase().includes(needle) ||
          String(flow.remotePort).includes(needle),
      ),
      findings: FINDINGS.filter(
        (finding) =>
          finding.title.toLowerCase().includes(needle) ||
          finding.description.toLowerCase().includes(needle) ||
          finding.relatedIp.includes(needle) ||
          finding.relatedFlow.toLowerCase().includes(needle) ||
          finding.technique.toLowerCase().includes(needle),
      ),
      dns: DNS_RECORDS.filter(
        (record) =>
          record.query.toLowerCase().includes(needle) ||
          record.answer.toLowerCase().includes(needle) ||
          record.type.toLowerCase().includes(needle),
      ),
      evidence: EVIDENCE.filter(
        (item) =>
          item.label.toLowerCase().includes(needle) ||
          item.id.toLowerCase().includes(needle) ||
          item.kind.toLowerCase().includes(needle),
      ),
    };
  }, [needle]);

  const total =
    results.packets.length +
    results.flows.length +
    results.findings.length +
    results.dns.length +
    results.evidence.length;

  return (
    <div className="flex flex-col">
      <PageHeader
        eyebrow="Investigation"
        title="Search the case"
        description="Type an address, port, domain, conversation ID or keyword. Every record in the session is checked at once."
      />

      <div className="grid gap-3 p-4">
        <Panel bodyClassName="p-3">
          <label className="flex items-center gap-2 border border-edge bg-d4 px-3">
            <SearchIcon className="size-4 text-t3" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              spellCheck={false}
              placeholder="203.0.113.47, 445, hosted-metrics.io…"
              className="w-full bg-transparent py-2 font-data text-sm text-t1 outline-none"
            />
            <span className="shrink-0 font-data text-[11px] text-t3">
              {needle ? `${formatNumber(total)} matches` : "waiting"}
            </span>
          </label>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {SUGGESTIONS.map((item) => (
              <button
                key={item}
                type="button"
                onClick={() => setQuery(item)}
                className="border border-edge bg-d3 px-2 py-1 font-data text-[11px] text-t2 hover:bg-d4 hover:text-t1"
              >
                {item}
              </button>
            ))}
          </div>
        </Panel>

        {!needle ? (
          <Notice tone="accent" title="Nothing searched yet">
            Pick one of the examples above, or type anything you saw elsewhere in the case.
          </Notice>
        ) : total === 0 ? (
          <Notice tone="wa" title="No matches">
            Nothing in this session mentions “{query}”. Check the spelling, or try a shorter piece of
            the address or name.
          </Notice>
        ) : (
          <div className="grid gap-3">
            {results.findings.length > 0 ? (
              <Panel title="Detections" hint={`${results.findings.length}`} bodyClassName="p-0">
                <DataTable head={["ID", "Severity", "Title", "Technique", "Address", "Conversation"]}>
                  {results.findings.map((finding) => (
                    <Row key={finding.id}>
                      <Cell className="text-t3">{finding.id}</Cell>
                      <Cell>
                        <SeverityPill severity={finding.severity} />
                      </Cell>
                      <Cell className="max-w-[24rem] truncate text-t1">{finding.title}</Cell>
                      <Cell className="max-w-[16rem] truncate">{finding.technique}</Cell>
                      <Cell>{finding.relatedIp}</Cell>
                      <Cell>{finding.relatedFlow}</Cell>
                    </Row>
                  ))}
                </DataTable>
              </Panel>
            ) : null}

            {results.flows.length > 0 ? (
              <Panel title="Conversations" hint={`${results.flows.length}`} bodyClassName="p-0">
                <DataTable head={["ID", "Proto", "Remote", "Host", "Out", "In", "Risk"]}>
                  {results.flows.map((flow) => (
                    <Row key={flow.id}>
                      <Cell className="text-t3">{flow.id}</Cell>
                      <Cell className="text-t1">{flow.protocol}</Cell>
                      <Cell>
                        {flow.remoteIp}:{flow.remotePort}
                      </Cell>
                      <Cell className="max-w-[16rem] truncate">{flow.remoteHost}</Cell>
                      <Cell>{formatBytes(flow.bytesOut)}</Cell>
                      <Cell>{formatBytes(flow.bytesIn)}</Cell>
                      <Cell>
                        <RiskPill risk={flow.risk} />
                      </Cell>
                    </Row>
                  ))}
                </DataTable>
              </Panel>
            ) : null}

            {results.dns.length > 0 ? (
              <Panel title="Name lookups" hint={`${results.dns.length}`} bodyClassName="p-0">
                <DataTable head={["Time", "Name", "Type", "Answer", "Count", "Verdict"]}>
                  {results.dns.map((record) => (
                    <Row key={record.query}>
                      <Cell>{record.time}</Cell>
                      <Cell className="max-w-[20rem] truncate text-t1">{record.query}</Cell>
                      <Cell>{record.type}</Cell>
                      <Cell className="max-w-[16rem] truncate">{record.answer}</Cell>
                      <Cell>{formatNumber(record.count)}</Cell>
                      <Cell>
                        <Tag tone={record.verdict === "OK" ? "ok" : record.verdict === "BLOCKED" ? "er" : "wa"}>
                          {record.verdict}
                        </Tag>
                      </Cell>
                    </Row>
                  ))}
                </DataTable>
              </Panel>
            ) : null}

            {results.evidence.length > 0 ? (
              <Panel title="Evidence" hint={`${results.evidence.length}`} bodyClassName="p-0">
                <DataTable head={["ID", "Kind", "Label", "Items", "Fingerprint", "Added"]}>
                  {results.evidence.map((item) => (
                    <Row key={item.id}>
                      <Cell className="text-t3">{item.id}</Cell>
                      <Cell>{item.kind}</Cell>
                      <Cell className="max-w-[22rem] truncate text-t1">{item.label}</Cell>
                      <Cell>{formatNumber(item.items)}</Cell>
                      <Cell>{item.hash}</Cell>
                      <Cell>{item.addedAt}</Cell>
                    </Row>
                  ))}
                </DataTable>
              </Panel>
            ) : null}

            {results.packets.length > 0 ? (
              <Panel
                title="Packets"
                hint={`first ${results.packets.length} matches`}
                bodyClassName="p-0"
              >
                <div className="max-h-96 overflow-y-auto">
                  <DataTable head={["#", "Time", "Proto", "Source", "Destination", "Len", "Risk", "Summary"]}>
                    {results.packets.map((packet) => (
                      <Row key={packet.number}>
                        <Cell className="text-t3">{packet.number}</Cell>
                        <Cell>{packet.time}</Cell>
                        <Cell className="text-t1">{packet.protocol}</Cell>
                        <Cell>
                          {packet.srcIp}
                          {packet.srcPort ? `:${packet.srcPort}` : ""}
                        </Cell>
                        <Cell>
                          {packet.dstIp}
                          {packet.dstPort ? `:${packet.dstPort}` : ""}
                        </Cell>
                        <Cell>{packet.size}</Cell>
                        <Cell>
                          <RiskPill risk={packet.risk} />
                        </Cell>
                        <Cell className="max-w-[18rem] truncate text-t3">{packet.summary}</Cell>
                      </Row>
                    ))}
                  </DataTable>
                </div>
              </Panel>
            ) : null}
          </div>
        )}
      </div>
    </div>
  );
}
