#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3403-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102815);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2017-11714", "CVE-2017-9611", "CVE-2017-9612", "CVE-2017-9726", "CVE-2017-9727", "CVE-2017-9739", "CVE-2017-9835");
  script_xref(name:"USN", value:"3403-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.04 : ghostscript vulnerabilities (USN-3403-1)");
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
"Kamil Frankowicz discovered that Ghostscript mishandles references. A
remote attacker could use this to cause a denial of service.
(CVE-2017-11714)

Kim Gwan Yeong discovered that Ghostscript could allow a heap-based
buffer over-read and application crash. A remote attacker could use a
crafted document to cause a denial of service. (CVE-2017-9611,
CVE-2017-9726, CVE-2017-9727, CVE-2017-9739)

Kim Gwan Yeong discovered an use-after-free vulnerability in
Ghostscript. A remote attacker could use a crafted file to cause a
denial of service. (CVE-2017-9612)

Kim Gwan Yeong discovered a lack of integer overflow check in
Ghostscript. A remote attacker could use crafted PostScript document
to cause a denial of service. (CVE-2017-9835).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3403-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs9-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/29");
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
if (! preg(pattern:"^(14\.04|16\.04|17\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 17.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"ghostscript", pkgver:"9.10~dfsg-0ubuntu10.10")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"ghostscript-x", pkgver:"9.10~dfsg-0ubuntu10.10")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libgs9", pkgver:"9.10~dfsg-0ubuntu10.10")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libgs9-common", pkgver:"9.10~dfsg-0ubuntu10.10")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"ghostscript", pkgver:"9.18~dfsg~0-0ubuntu2.7")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"ghostscript-x", pkgver:"9.18~dfsg~0-0ubuntu2.7")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libgs9", pkgver:"9.18~dfsg~0-0ubuntu2.7")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libgs9-common", pkgver:"9.18~dfsg~0-0ubuntu2.7")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"ghostscript", pkgver:"9.19~dfsg+1-0ubuntu7.6")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"ghostscript-x", pkgver:"9.19~dfsg+1-0ubuntu7.6")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"libgs9", pkgver:"9.19~dfsg+1-0ubuntu7.6")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"libgs9-common", pkgver:"9.19~dfsg+1-0ubuntu7.6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-x / libgs9 / libgs9-common");
}
