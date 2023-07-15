#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4336-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(135966);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-1000876", "CVE-2018-10372", "CVE-2018-10373", "CVE-2018-10534", "CVE-2018-10535", "CVE-2018-12641", "CVE-2018-12697", "CVE-2018-12698", "CVE-2018-12699", "CVE-2018-12700", "CVE-2018-12934", "CVE-2018-13033", "CVE-2018-17358", "CVE-2018-17359", "CVE-2018-17360", "CVE-2018-17794", "CVE-2018-17985", "CVE-2018-18309", "CVE-2018-18483", "CVE-2018-18484", "CVE-2018-18605", "CVE-2018-18606", "CVE-2018-18607", "CVE-2018-18700", "CVE-2018-18701", "CVE-2018-19931", "CVE-2018-19932", "CVE-2018-20002", "CVE-2018-20623", "CVE-2018-20651", "CVE-2018-20671", "CVE-2018-8945", "CVE-2018-9138", "CVE-2019-12972", "CVE-2019-14250", "CVE-2019-14444", "CVE-2019-17450", "CVE-2019-17451", "CVE-2019-9070", "CVE-2019-9071", "CVE-2019-9073", "CVE-2019-9074", "CVE-2019-9075", "CVE-2019-9077");
  script_xref(name:"USN", value:"4336-1");

  script_name(english:"Ubuntu 18.04 LTS : GNU binutils vulnerabilities (USN-4336-1)");
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
"It was discovered that GNU binutils contained a large number of
security issues. If a user or automated system were tricked into
processing a specially crafted file, a remote attacker could cause GNU
binutils to crash, resulting in a denial of service, or possibly
execute arbitrary code.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4336-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected binutils and / or binutils-multiarch packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/24");
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
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"binutils", pkgver:"2.30-21ubuntu1~18.04.3")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"binutils-multiarch", pkgver:"2.30-21ubuntu1~18.04.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / binutils-multiarch");
}
