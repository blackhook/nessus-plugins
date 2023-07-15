#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2021-350-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156121);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id("CVE-2021-4008", "CVE-2021-4009");

  script_name(english:"Slackware Linux 14.0 / 14.1 / 14.2 / current xorg-server  Multiple Vulnerabilities (SSA:2021-350-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to xorg-server.");
  script_set_attribute(attribute:"description", value:
"The version of xorg-server installed on the remote host is prior to 1.12.4 / 1.14.3 / 1.18.3 / 1.20.14 / 21.1.4. It is,
therefore, affected by multiple vulnerabilities as referenced in the SSA:2021-350-01 advisory.

  - A flaw was found in xorg-x11-server in versions before 21.1.2 and before 1.20.14. An out-of-bounds access
    can occur in the SProcXFixesCreatePointerBarrier function. The highest threat from this vulnerability is
    to data confidentiality and integrity as well as system availability. (CVE-2021-4009)

  - A flaw was found in xorg-x11-server in versions before 21.1.2 and before 1.20.14. An out-of-bounds access
    can occur in the SProcRenderCompositeGlyphs function. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system availability. (CVE-2021-4008)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected xorg-server package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4009");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server-xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server-xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server-xwayland");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    { 'fixed_version' : '1.12.4', 'product' : 'xorg-server', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '6_slack14.0', 'arch' : 'i486' },
    { 'fixed_version' : '1.12.4', 'product' : 'xorg-server-xephyr', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '6_slack14.0', 'arch' : 'i486' },
    { 'fixed_version' : '1.12.4', 'product' : 'xorg-server-xnest', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '6_slack14.0', 'arch' : 'i486' },
    { 'fixed_version' : '1.12.4', 'product' : 'xorg-server-xvfb', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '6_slack14.0', 'arch' : 'i486' },
    { 'fixed_version' : '1.12.4', 'product' : 'xorg-server', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '6_slack14.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.12.4', 'product' : 'xorg-server-xephyr', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '6_slack14.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.12.4', 'product' : 'xorg-server-xnest', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '6_slack14.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.12.4', 'product' : 'xorg-server-xvfb', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '6_slack14.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.14.3', 'product' : 'xorg-server', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '7_slack14.1', 'arch' : 'i486' },
    { 'fixed_version' : '1.14.3', 'product' : 'xorg-server-xephyr', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '7_slack14.1', 'arch' : 'i486' },
    { 'fixed_version' : '1.14.3', 'product' : 'xorg-server-xnest', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '7_slack14.1', 'arch' : 'i486' },
    { 'fixed_version' : '1.14.3', 'product' : 'xorg-server-xvfb', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '7_slack14.1', 'arch' : 'i486' },
    { 'fixed_version' : '1.14.3', 'product' : 'xorg-server', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '7_slack14.1', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.14.3', 'product' : 'xorg-server-xephyr', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '7_slack14.1', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.14.3', 'product' : 'xorg-server-xnest', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '7_slack14.1', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.14.3', 'product' : 'xorg-server-xvfb', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '7_slack14.1', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.18.3', 'product' : 'xorg-server', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '6_slack14.2', 'arch' : 'i586' },
    { 'fixed_version' : '1.18.3', 'product' : 'xorg-server-xephyr', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '6_slack14.2', 'arch' : 'i586' },
    { 'fixed_version' : '1.18.3', 'product' : 'xorg-server-xnest', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '6_slack14.2', 'arch' : 'i586' },
    { 'fixed_version' : '1.18.3', 'product' : 'xorg-server-xvfb', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '6_slack14.2', 'arch' : 'i586' },
    { 'fixed_version' : '1.18.3', 'product' : 'xorg-server', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '6_slack14.2', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.18.3', 'product' : 'xorg-server-xephyr', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '6_slack14.2', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.18.3', 'product' : 'xorg-server-xnest', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '6_slack14.2', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.18.3', 'product' : 'xorg-server-xvfb', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '6_slack14.2', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.20.14', 'product' : 'xorg-server', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '1.20.14', 'product' : 'xorg-server-xephyr', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '1.20.14', 'product' : 'xorg-server-xnest', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '1.20.14', 'product' : 'xorg-server-xvfb', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '21.1.4', 'product' : 'xorg-server-xwayland', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '1.20.14', 'product' : 'xorg-server', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.20.14', 'product' : 'xorg-server-xephyr', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.20.14', 'product' : 'xorg-server-xnest', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.20.14', 'product' : 'xorg-server-xvfb', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '21.1.4', 'product' : 'xorg-server-xwayland', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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
