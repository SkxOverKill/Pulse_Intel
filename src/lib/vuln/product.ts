/// Heuristic product/vendor extraction from an NVD description, used only to
/// visually club near-duplicate CVEs on the vulnerabilities list (e.g. the
/// dozens of distinct "Linux Kernel" CVEs that otherwise dominate the page).
/// This is a display grouping, not a data model change — every CVE is still
/// its own row underneath, just collapsed by default.
const KNOWN_PRODUCTS = [
  "linux kernel",
  "windows",
  "google chrome",
  "chrome",
  "mozilla firefox",
  "firefox",
  "apache http server",
  "apache tomcat",
  "apache struts",
  "apache",
  "wordpress",
  "cisco",
  "fortinet",
  "fortios",
  "ivanti",
  "microsoft exchange",
  "sql server",
  "docker",
  "kubernetes",
  "openssl",
  "android",
  "adobe acrobat",
  "adobe",
  "vmware",
  "sap",
  "oracle",
  "postgresql",
  "mysql",
  "juniper",
  "citrix",
  "sonicwall",
  "paloalto",
  "palo alto",
];

export function extractProduct(description: string | null): string | null {
  if (!description) return null;
  const lower = description.toLowerCase();
  for (const product of KNOWN_PRODUCTS) {
    if (lower.includes(product)) {
      return product.replace(/\b\w/g, (c) => c.toUpperCase());
    }
  }
  return null;
}
