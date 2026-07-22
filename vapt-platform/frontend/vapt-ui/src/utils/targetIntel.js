export function targetOf(finding) {
  const metadata = finding?.finding_metadata || {};
  return metadata.host || metadata.hostname || metadata.ip_address || metadata.target || metadata.url || metadata.affected_url || "n/a";
}

export function humanSource(source) {
  if (source === "network-db" || source === "openvas") return "Network";
  if (source === "zap") return "Web";
  if (source === "mobsf") return "Mobile";
  return source || "Unknown";
}

function normalized(value) {
  return String(value || "").trim().toLowerCase();
}

function formatPlatformLabel(value) {
  const label = String(value || "").trim();
  if (!label) return "";
  const key = normalized(label);
  const mappings = {
    windows: "Windows",
    "windows 11": "Windows 11",
    "windows 10": "Windows 10",
    "windows server": "Windows Server",
    ubuntu: "Ubuntu",
    debian: "Debian",
    linux: "Linux",
    "red hat enterprise linux": "Red Hat Enterprise Linux",
    rhel: "Red Hat Enterprise Linux",
    centos: "CentOS",
    rocky: "Rocky Linux",
    almalinux: "AlmaLinux",
    macos: "macOS",
    "mac os": "macOS",
    darwin: "macOS",
    freebsd: "FreeBSD",
    openbsd: "OpenBSD",
    pfsense: "pfSense",
    network: "Network Device OS",
    network_device: "Network Device OS",
    server: "Server OS",
    web: "Web Platform",
    database: "Database Platform",
    container: "Container Host",
    saas: "SaaS Platform",
  };
  return mappings[key] || label;
}

function platformFromEvidence(asset, metadata = {}) {
  const evidence = [
    asset?.os,
    asset?.asset_name,
    metadata.os_name,
    metadata.asset_os,
    metadata.os,
    metadata.os_family,
    metadata.server,
    metadata.banner,
    metadata.service_banner,
    metadata.product,
  ]
    .filter(Boolean)
    .join(" ");
  const hay = normalized(evidence);
  if (!hay) return "";

  if (/(windows server|microsoft windows|windows)/.test(hay)) return "Windows";
  if (/(ubuntu)/.test(hay)) return "Ubuntu";
  if (/(debian)/.test(hay)) return "Debian";
  if (/(red hat|rhel)/.test(hay)) return "Red Hat Enterprise Linux";
  if (/(centos)/.test(hay)) return "CentOS";
  if (/(rocky)/.test(hay)) return "Rocky Linux";
  if (/(almalinux)/.test(hay)) return "AlmaLinux";
  if (/(freebsd)/.test(hay)) return "FreeBSD";
  if (/(openbsd)/.test(hay)) return "OpenBSD";
  if (/(macos|mac os|darwin)/.test(hay)) return "macOS";
  if (/(pfsense)/.test(hay)) return "pfSense";
  if (/(avaya g430|avaya device manager)/.test(hay)) return "Avaya Appliance";
  if (/(canon http server|canon)/.test(hay)) return "Canon Embedded Device";
  if (/(fortinet|juniper|mikrotik|palo alto|cisco ios|routeros|switchos)/.test(hay)) return "Network Device OS";
  if (/(samba|microsoft-ds|rdp)/.test(hay)) return "Windows";
  if (/(rpcbind|nfs)/.test(hay)) return "Linux";
  if (/(postgresql|mariadb|mysql)/.test(hay)) return "Database Platform";
  if (/(nginx|apache|iis|http server|ntopng|zabbix)/.test(hay)) return "Web Platform";
  if (/(linux)/.test(hay)) return "Linux";
  return "";
}

export function resolveAssetForTarget(target, assets = []) {
  const needle = normalized(target);
  if (!needle) return null;
  return assets.find((asset) =>
    [asset.asset_name, asset.name, asset.hostname, asset.ip_address, asset.url]
      .filter(Boolean)
      .some((value) => {
        const hay = normalized(value);
        return hay === needle || hay.includes(needle) || needle.includes(hay);
      })
  ) || null;
}

export function resolveOsLabel({ finding = null, asset = null, findings = [], assets = [], target = "" } = {}) {
  if (asset?.os) return formatPlatformLabel(asset.os);
  const metadata = finding?.finding_metadata || {};
  if (metadata.os_name) return formatPlatformLabel(metadata.os_name);
  if (metadata.asset_os) return formatPlatformLabel(metadata.asset_os);
  if (metadata.os) return formatPlatformLabel(metadata.os);

  const evidenced = platformFromEvidence(asset, metadata);
  if (evidenced) return evidenced;

  const family = formatPlatformLabel(metadata.os_family);
  if (family) return family;

  const targetAsset = asset || resolveAssetForTarget(target || targetOf(finding), assets);
  if (targetAsset?.os) return formatPlatformLabel(targetAsset.os);
  const targetEvidenced = platformFromEvidence(targetAsset, metadata);
  if (targetEvidenced) return targetEvidenced;

  const needle = normalized(target || targetOf(finding));
  const related = (findings || []).filter((item) => normalized(targetOf(item)) === needle || normalized(targetOf(item)).includes(needle) || needle.includes(normalized(targetOf(item))));
  for (const relatedFinding of related) {
    const label = resolveOsLabel({ finding: relatedFinding, assets, target: needle });
    if (label && label !== "Not fingerprinted") return label;
  }

  return "Not fingerprinted";
}
