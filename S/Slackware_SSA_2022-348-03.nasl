#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2022-348-03. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168742);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/20");

  script_cve_id(
    "CVE-2022-4283",
    "CVE-2022-46340",
    "CVE-2022-46341",
    "CVE-2022-46342",
    "CVE-2022-46343",
    "CVE-2022-46344"
  );

  script_name(english:"Slackware Linux 15.0 / current xorg-server  Multiple Vulnerabilities (SSA:2022-348-03)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to xorg-server.");
  script_set_attribute(attribute:"description", value:
"The version of xorg-server installed on the remote host is prior to 1.20.14 / 21.1.4 / 21.1.5 / 22.1.6. It is,
therefore, affected by multiple vulnerabilities as referenced in the SSA:2022-348-03 advisory.

  - A vulnerability was found in X.Org. This security flaw occurs because the XkbCopyNames function left a
    dangling pointer to freed memory, resulting in out-of-bounds memory access on subsequent XkbGetKbdByName
    requests.. This issue can lead to local privileges elevation on systems where the X server is running
    privileged and remote code execution for ssh X forwarding sessions. (CVE-2022-4283)

  - A vulnerability was found in X.Org. This security flaw occurs becuase the swap handler for the
    XTestFakeInput request of the XTest extension may corrupt the stack if GenericEvents with lengths larger
    than 32 bytes are sent through a the XTestFakeInput request. This issue can lead to local privileges
    elevation on systems where the X server is running privileged and remote code execution for ssh X
    forwarding sessions. This issue does not affect systems where client and server use the same byte order.
    (CVE-2022-46340)

  - A vulnerability was found in X.Org. This security flaw occurs because the handler for the XIPassiveUngrab
    request accesses out-of-bounds memory when invoked with a high keycode or button code. This issue can lead
    to local privileges elevation on systems where the X server is running privileged and remote code
    execution for ssh X forwarding sessions. (CVE-2022-46341)

  - A vulnerability was found in X.Org. This security flaw occurs because the handler for the
    XvdiSelectVideoNotify request may write to memory after it has been freed. This issue can lead to local
    privileges elevation on systems where the X se (CVE-2022-46342)

  - A vulnerability was found in X.Org. This security flaw occurs because the handler for the
    ScreenSaverSetAttributes request may write to memory after it has been freed. This issue can lead to local
    privileges elevation on systems where the X server is running privileged and remote code execution for ssh
    X forwarding sessions. (CVE-2022-46343)

  - A vulnerability was found in X.Org. This security flaw occurs because the handler for the XIChangeProperty
    request has a length-validation issues, resulting in out-of-bounds memory reads and potential information
    disclosure. This issue can lead to local privileges elevation on systems where the X server is running
    privileged and remote code execution for ssh X forwarding sessions. (CVE-2022-46344)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected xorg-server package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46344");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server-xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server-xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server-xwayland");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    { 'fixed_version' : '1.20.14', 'product' : 'xorg-server', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '5_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '1.20.14', 'product' : 'xorg-server-xephyr', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '5_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '1.20.14', 'product' : 'xorg-server-xnest', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '5_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '1.20.14', 'product' : 'xorg-server-xvfb', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '5_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '21.1.4', 'product' : 'xorg-server-xwayland', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '4_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '1.20.14', 'product' : 'xorg-server', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '5_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.20.14', 'product' : 'xorg-server-xephyr', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '5_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.20.14', 'product' : 'xorg-server-xnest', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '5_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.20.14', 'product' : 'xorg-server-xvfb', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '5_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '21.1.4', 'product' : 'xorg-server-xwayland', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '4_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '21.1.5', 'product' : 'xorg-server', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '21.1.5', 'product' : 'xorg-server-xephyr', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '21.1.5', 'product' : 'xorg-server-xnest', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '21.1.5', 'product' : 'xorg-server-xvfb', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '22.1.6', 'product' : 'xorg-server-xwayland', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '21.1.5', 'product' : 'xorg-server', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '21.1.5', 'product' : 'xorg-server-xephyr', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '21.1.5', 'product' : 'xorg-server-xnest', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '21.1.5', 'product' : 'xorg-server-xvfb', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '22.1.6', 'product' : 'xorg-server-xwayland', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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
