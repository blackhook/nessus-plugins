#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2022-076-02. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159055);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/03");

  script_cve_id("CVE-2022-0778");
  script_xref(name:"IAVA", value:"2022-A-0121-S");

  script_name(english:"Slackware Linux 14.2 / 15.0 / current openssl  Vulnerability (SSA:2022-076-02)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to openssl.");
  script_set_attribute(attribute:"description", value:
"The version of openssl installed on the remote host is prior to 1.0.2u / 1.1.1n. It is, therefore, affected by a
vulnerability as referenced in the SSA:2022-076-02 advisory.

  - The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop
    forever for non-prime moduli. Internally this function is used when parsing certificates that contain
    elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point
    encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has
    invalid explicit curve parameters. Since certificate parsing happens prior to verification of the
    certificate signature, any process that parses an externally supplied certificate may thus be subject to a
    denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they
    can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients
    consuming server certificates - TLS servers consuming client certificates - Hosting providers taking
    certificates or private keys from customers - Certificate authorities parsing certification requests from
    subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that
    use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS
    issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate
    which makes it slightly harder to trigger the infinite loop. However any operation which requires the
    public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-
    signed certificate to trigger the loop during verification of the certificate signature. This issue
    affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the
    15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected
    1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc). (CVE-2022-0778)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected openssl package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0778");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:openssl-solibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '1.0.2u', 'product' : 'openssl', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '2_slack14.2', 'arch' : 'i586' },
    { 'fixed_version' : '1.0.2u', 'product' : 'openssl-solibs', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '2_slack14.2', 'arch' : 'i586' },
    { 'fixed_version' : '1.0.2u', 'product' : 'openssl', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '2_slack14.2', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.0.2u', 'product' : 'openssl-solibs', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '2_slack14.2', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.1.1n', 'product' : 'openssl', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '1.1.1n', 'product' : 'openssl-solibs', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '1.1.1n', 'product' : 'openssl', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.1.1n', 'product' : 'openssl-solibs', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.1.1n', 'product' : 'openssl', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '1.1.1n', 'product' : 'openssl-solibs', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '1.1.1n', 'product' : 'openssl', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.1.1n', 'product' : 'openssl-solibs', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
];

foreach constraint (constraints) {
    var pkg_arch = constraint['arch'];
    var arch = NULL;
    if (pkg_arch == "x86_64") {
        arch = pkg_arch;
    }
    if (slackware_check(osver:constraint['os_version'],
                        arch:arch,
                        pkgname:constraint['product'],
                        pkgver:constraint['fixed_version'],
                        pkgarch:pkg_arch,
                        pkgnum:constraint['service_pack'])) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
