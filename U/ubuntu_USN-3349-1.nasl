#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3349-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101263);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2016-2519", "CVE-2016-7426", "CVE-2016-7427", "CVE-2016-7428", "CVE-2016-7429", "CVE-2016-7431", "CVE-2016-7433", "CVE-2016-7434", "CVE-2016-9042", "CVE-2016-9310", "CVE-2016-9311", "CVE-2017-6458", "CVE-2017-6460", "CVE-2017-6462", "CVE-2017-6463", "CVE-2017-6464");
  script_xref(name:"USN", value:"3349-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 16.10 / 17.04 : ntp vulnerabilities (USN-3349-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Yihan Lian discovered that NTP incorrectly handled certain large
request data values. A remote attacker could possibly use this issue
to cause NTP to crash, resulting in a denial of service. This issue
only affected Ubuntu 16.04 LTS. (CVE-2016-2519)

Miroslav Lichvar discovered that NTP incorrectly handled certain
spoofed addresses when performing rate limiting. A remote attacker
could possibly use this issue to perform a denial of service. This
issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, and Ubuntu
16.10. (CVE-2016-7426)

Matthew Van Gundy discovered that NTP incorrectly handled certain
crafted broadcast mode packets. A remote attacker could possibly use
this issue to perform a denial of service. This issue only affected
Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, and Ubuntu 16.10. (CVE-2016-7427,
CVE-2016-7428)

Miroslav Lichvar discovered that NTP incorrectly handled certain
responses. A remote attacker could possibly use this issue to perform
a denial of service. This issue only affected Ubuntu 14.04 LTS, Ubuntu
16.04 LTS, and Ubuntu 16.10. (CVE-2016-7429)

Sharon Goldberg and Aanchal Malhotra discovered that NTP incorrectly
handled origin timestamps of zero. A remote attacker could possibly
use this issue to bypass the origin timestamp protection mechanism.
This issue only affected Ubuntu 16.10. (CVE-2016-7431)

Brian Utterback, Sharon Goldberg and Aanchal Malhotra discovered that
NTP incorrectly performed initial sync calculations. This issue only
applied to Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-7433)

Magnus Stubman discovered that NTP incorrectly handled certain mrulist
queries. A remote attacker could possibly use this issue to cause NTP
to crash, resulting in a denial of service. This issue only affected
Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-7434)

Matthew Van Gund discovered that NTP incorrectly handled origin
timestamp checks. A remote attacker could possibly use this issue to
perform a denial of service. This issue only affected Ubuntu Ubuntu
16.10, and Ubuntu 17.04. (CVE-2016-9042)

Matthew Van Gundy discovered that NTP incorrectly handled certain
control mode packets. A remote attacker could use this issue to set or
unset traps. This issue only applied to Ubuntu 14.04 LTS, Ubuntu 16.04
LTS and Ubuntu 16.10. (CVE-2016-9310)

Matthew Van Gundy discovered that NTP incorrectly handled the trap
service. A remote attacker could possibly use this issue to cause NTP
to crash, resulting in a denial of service. This issue only applied to
Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-9311)

It was discovered that NTP incorrectly handled memory when processing
long variables. A remote authenticated user could possibly use this
issue to cause NTP to crash, resulting in a denial of service.
(CVE-2017-6458)

It was discovered that NTP incorrectly handled memory when processing
long variables. A remote authenticated user could possibly use this
issue to cause NTP to crash, resulting in a denial of service. This
issue only applied to Ubuntu 16.04 LTS, Ubuntu 16.10 and Ubuntu 17.04.
(CVE-2017-6460)

It was discovered that the NTP legacy DPTS refclock driver incorrectly
handled the /dev/datum device. A local attacker could possibly use
this issue to cause a denial of service. (CVE-2017-6462)

It was discovered that NTP incorrectly handled certain invalid
settings in a :config directive. A remote authenticated user could
possibly use this issue to cause NTP to crash, resulting in a denial
of service. (CVE-2017-6463)

It was discovered that NTP incorrectly handled certain invalid mode
configuration directives. A remote authenticated user could possibly
use this issue to cause NTP to crash, resulting in a denial of
service. (CVE-2017-6464).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3349-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017-2023 Canonical, Inc. / NASL script (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
var release = chomp(release);
if (! preg(pattern:"^(14\.04|16\.04|16\.10|17\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 16.10 / 17.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"ntp", pkgver:"1:4.2.6.p5+dfsg-3ubuntu2.14.04.11")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"ntp", pkgver:"1:4.2.8p4+dfsg-3ubuntu5.5")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"ntp", pkgver:"1:4.2.8p8+dfsg-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"ntp", pkgver:"1:4.2.8p9+dfsg-2ubuntu1.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
