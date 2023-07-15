#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2023-153-02. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176640);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/02");

  script_cve_id(
    "CVE-2023-26551",
    "CVE-2023-26552",
    "CVE-2023-26553",
    "CVE-2023-26554",
    "CVE-2023-26555"
  );

  script_name(english:"Slackware Linux 14.0 / 14.1 / 14.2 / 15.0 / current ntp  Multiple Vulnerabilities (SSA:2023-153-02)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to ntp.");
  script_set_attribute(attribute:"description", value:
"The version of ntp installed on the remote host is prior to 4.2.8p16. It is, therefore, affected by multiple
vulnerabilities as referenced in the SSA:2023-153-02 advisory.

  - mstolfp in libntp/mstolfp.c in NTP 4.2.8p15 has an out-of-bounds write in the cp<cpdec while loop. An
    adversary may be able to attack a client ntpq process, but cannot attack ntpd. (CVE-2023-26551)

  - mstolfp in libntp/mstolfp.c in NTP 4.2.8p15 has an out-of-bounds write when adding a decimal point. An
    adversary may be able to attack a client ntpq process, but cannot attack ntpd. (CVE-2023-26552)

  - mstolfp in libntp/mstolfp.c in NTP 4.2.8p15 has an out-of-bounds write when copying the trailing number.
    An adversary may be able to attack a client ntpq process, but cannot attack ntpd. (CVE-2023-26553)

  - mstolfp in libntp/mstolfp.c in NTP 4.2.8p15 has an out-of-bounds write when adding a '\0' character. An
    adversary may be able to attack a client ntpq process, but cannot attack ntpd. (CVE-2023-26554)

  - praecis_parse in ntpd/refclock_palisade.c in NTP 4.2.8p15 has an out-of-bounds write. Any attack method
    would be complex, e.g., with a manipulated GPS receiver. (CVE-2023-26555)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.467753
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0a80b2e");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected ntp package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26555");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    { 'fixed_version' : '4.2.8p16', 'product' : 'ntp', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '1_slack14.0', 'arch' : 'i486' },
    { 'fixed_version' : '4.2.8p16', 'product' : 'ntp', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '1_slack14.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '4.2.8p16', 'product' : 'ntp', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '1_slack14.1', 'arch' : 'i486' },
    { 'fixed_version' : '4.2.8p16', 'product' : 'ntp', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '1_slack14.1', 'arch' : 'x86_64' },
    { 'fixed_version' : '4.2.8p16', 'product' : 'ntp', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '1_slack14.2', 'arch' : 'i586' },
    { 'fixed_version' : '4.2.8p16', 'product' : 'ntp', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '1_slack14.2', 'arch' : 'x86_64' },
    { 'fixed_version' : '4.2.8p16', 'product' : 'ntp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '4.2.8p16', 'product' : 'ntp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '4.2.8p16', 'product' : 'ntp', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '4.2.8p16', 'product' : 'ntp', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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
