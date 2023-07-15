#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2022-320-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167778);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/06");

  script_cve_id("CVE-2022-42898");
  script_xref(name:"IAVB", value:"2022-B-0052");

  script_name(english:"Slackware Linux 15.0 / current krb5  Vulnerability (SSA:2022-320-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to krb5.");
  script_set_attribute(attribute:"description", value:
"The version of krb5 installed on the remote host is prior to 1.19.2 / 1.20.1. It is, therefore, affected by a
vulnerability as referenced in the SSA:2022-320-01 advisory.

  - The Kerberos libraries used by Samba provide a mechanism for authenticating a user or service by means of
    tickets that can contain Privilege Attribute Certificates (PACs). Both the Heimdal and MIT Kerberos
    libraries, and so the embedded Heimdal shipped by Samba suffer from an integer multiplication overflow
    when calculating how many bytes to allocate for a buffer for the parsed PAC. On a 32-bit system an
    overflow allows placement of 16-byte chunks of entirely attacker- controlled data. (Because the user's
    control over this calculation is limited to an unsigned 32-bit value, 64-bit systems are not impacted).
    The server most vulnerable is the KDC, as it will parse an attacker-controlled PAC in the S4U2Proxy
    handler. The secondary risk is to Kerberos-enabled file server installations in a non-AD realm. A non-AD
    Heimdal KDC controlling such a realm may pass on an attacker-controlled PAC within the service ticket.
    (CVE-2022-42898)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected krb5 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42898");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '1.19.2', 'product' : 'krb5', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '3_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '1.19.2', 'product' : 'krb5', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '3_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.20.1', 'product' : 'krb5', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '1.20.1', 'product' : 'krb5', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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
      severity   : SECURITY_HOLE,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
