#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4379-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(137045);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-1000852", "CVE-2019-17177", "CVE-2020-11042", "CVE-2020-11044", "CVE-2020-11045", "CVE-2020-11046", "CVE-2020-11047", "CVE-2020-11048", "CVE-2020-11049", "CVE-2020-11058", "CVE-2020-11521", "CVE-2020-11522", "CVE-2020-11523", "CVE-2020-11524", "CVE-2020-11525", "CVE-2020-11526", "CVE-2020-13396", "CVE-2020-13397", "CVE-2020-13398");
  script_xref(name:"USN", value:"4379-1");

  script_name(english:"Ubuntu 18.04 LTS / 19.10 / 20.04 : freerdp2 vulnerabilities (USN-4379-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that FreeRDP incorrectly handled certain memory
operations. A remote attacker could use this issue to cause FreeRDP to
crash, resulting in a denial of service, or possibly exeucte arbitrary
code.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4379-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected libfreerdp-client2-2, libfreerdp-server2-2 and /
or libfreerdp2-2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13398");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-client2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-server2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp2-2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(18\.04|19\.10|20\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04 / 19.10 / 20.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"libfreerdp-client2-2", pkgver:"2.1.1+dfsg1-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libfreerdp-server2-2", pkgver:"2.1.1+dfsg1-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libfreerdp2-2", pkgver:"2.1.1+dfsg1-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libfreerdp-client2-2", pkgver:"2.1.1+dfsg1-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libfreerdp-server2-2", pkgver:"2.1.1+dfsg1-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libfreerdp2-2", pkgver:"2.1.1+dfsg1-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"libfreerdp-client2-2", pkgver:"2.1.1+dfsg1-0ubuntu0.20.04.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"libfreerdp-server2-2", pkgver:"2.1.1+dfsg1-0ubuntu0.20.04.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"libfreerdp2-2", pkgver:"2.1.1+dfsg1-0ubuntu0.20.04.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libfreerdp-client2-2 / libfreerdp-server2-2 / libfreerdp2-2");
}
