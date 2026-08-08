import "server-only";

import {
  Document,
  Page,
  StyleSheet,
  Text,
  View,
  renderToBuffer,
} from "@react-pdf/renderer";

export const CERTIFICATE_TITLE = "Tamper-Evident Consent Evidence Record";

type EvidenceDocument = {
  schema_version?: number;
  subject?: { email?: string; phone?: string };
  controller?: string;
  purpose?: string;
  disclosure?: { version?: string; text?: string };
  affirmative_action?: string;
  form_url?: string;
  origin?: string;
  occurred_at?: string;
  received_at?: string;
  retention_expires_at?: string;
  network?: { trusted_ip?: string | null; source?: string | null };
};

export type EvidenceCertificateInput = {
  certificateCode: string;
  consentId: string;
  payloadSha256: string;
  signatureHmac: string;
  signatureKeyVersion: number;
  verified: boolean;
  evidence: EvidenceDocument;
};

const styles = StyleSheet.create({
  page: {
    backgroundColor: "#f4efe4",
    color: "#171a16",
    fontFamily: "Helvetica",
    fontSize: 9,
    lineHeight: 1.45,
    padding: 42,
  },
  header: {
    borderBottomColor: "#274e3b",
    borderBottomWidth: 2,
    marginBottom: 18,
    paddingBottom: 14,
  },
  eyebrow: {
    color: "#ad4f23",
    fontSize: 8,
    letterSpacing: 1.4,
    marginBottom: 6,
    textTransform: "uppercase",
  },
  title: { fontFamily: "Helvetica-Bold", fontSize: 18 },
  status: {
    backgroundColor: "#dce8df",
    borderColor: "#274e3b",
    borderRadius: 2,
    borderWidth: 1,
    color: "#274e3b",
    marginBottom: 16,
    padding: 10,
  },
  section: { marginBottom: 14 },
  sectionTitle: {
    color: "#274e3b",
    fontFamily: "Helvetica-Bold",
    fontSize: 10,
    marginBottom: 5,
    textTransform: "uppercase",
  },
  row: { display: "flex", flexDirection: "row", marginBottom: 4 },
  label: { color: "#5b625c", width: 132 },
  value: { flex: 1 },
  disclosure: {
    backgroundColor: "#ebe4d7",
    borderLeftColor: "#ad4f23",
    borderLeftWidth: 3,
    padding: 10,
  },
  digest: { fontFamily: "Courier", fontSize: 7.5 },
  footer: {
    borderTopColor: "#a8aa9e",
    borderTopWidth: 1,
    color: "#5b625c",
    fontSize: 7,
    marginTop: "auto",
    paddingTop: 10,
  },
});

function safeText(value: unknown, fallback = "Not recorded"): string {
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

function EvidenceRow({ label, value, digest = false }: {
  label: string;
  value: unknown;
  digest?: boolean;
}) {
  return (
    <View style={styles.row}>
      <Text style={styles.label}>{label}</Text>
      <Text style={digest ? [styles.value, styles.digest] : styles.value}>
        {safeText(value)}
      </Text>
    </View>
  );
}

function CertificateDocument({ input }: { input: EvidenceCertificateInput }) {
  const evidence = input.evidence;
  const subject = [evidence.subject?.email, evidence.subject?.phone]
    .filter(Boolean)
    .join(" / ");
  const network = evidence.network?.trusted_ip
    ? `${evidence.network.trusted_ip} (${safeText(evidence.network.source)})`
    : "No trusted-edge IP recorded";

  return (
    <Document
      title={CERTIFICATE_TITLE}
      author="Opt-in Vault"
      subject="Consent evidence integrity record"
      keywords="consent,evidence,integrity"
    >
      <Page size="A4" style={styles.page}>
        <View style={styles.header}>
          <Text style={styles.eyebrow}>Opt-in Vault / Evidence Export</Text>
          <Text style={styles.title}>{CERTIFICATE_TITLE}</Text>
        </View>

        <Text style={styles.status}>
          {input.verified
            ? "VERIFIED — Stored content matches its SHA-256 digest and versioned HMAC."
            : "NOT VERIFIED — Do not rely on this export."}
        </Text>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Record identity</Text>
          <EvidenceRow label="Certificate code" value={input.certificateCode} />
          <EvidenceRow label="Consent record" value={input.consentId} />
          <EvidenceRow label="Subject" value={subject} />
          <EvidenceRow label="Controller" value={evidence.controller} />
          <EvidenceRow label="Purpose" value={evidence.purpose} />
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Affirmative event</Text>
          <EvidenceRow label="Action" value={evidence.affirmative_action} />
          <EvidenceRow label="Occurred" value={evidence.occurred_at} />
          <EvidenceRow label="Server received" value={evidence.received_at} />
          <EvidenceRow label="Form URL" value={evidence.form_url} />
          <EvidenceRow label="Trusted network" value={network} />
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Registered disclosure</Text>
          <View style={styles.disclosure}>
            <Text>Version: {safeText(evidence.disclosure?.version)}</Text>
            <Text>{safeText(evidence.disclosure?.text)}</Text>
          </View>
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Integrity envelope</Text>
          <EvidenceRow label="SHA-256" value={input.payloadSha256} digest />
          <EvidenceRow label="HMAC signature" value={input.signatureHmac} digest />
          <EvidenceRow label="Signature key version" value={String(input.signatureKeyVersion)} />
          <EvidenceRow label="Retention deadline" value={evidence.retention_expires_at} />
        </View>

        <Text style={styles.footer}>
          This record is tamper-evident evidence of what Opt-in Vault received. It is not
          independent proof of identity and is not a legal-compliance determination.
        </Text>
      </Page>
    </Document>
  );
}

export async function renderEvidenceCertificate(
  input: EvidenceCertificateInput,
): Promise<Buffer> {
  if (!input.verified) throw new Error("Unverified consent evidence cannot be exported.");
  return renderToBuffer(<CertificateDocument input={input} />);
}
