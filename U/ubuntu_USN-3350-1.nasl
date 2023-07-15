#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3350-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101354);
  script_version("3.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2017-2820", "CVE-2017-7511", "CVE-2017-7515", "CVE-2017-9083", "CVE-2017-9406", "CVE-2017-9408", "CVE-2017-9775");
  script_xref(name:"USN", value:"3350-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 16.10 / 17.04 : poppler vulnerabilities (USN-3350-1)");
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
"Aleksandar Nikolic discovered that poppler incorrectly handled JPEG
2000 images. If a user or automated system were tricked into opening a
crafted PDF file, an attacker could cause a denial of service or
possibly execute arbitrary code with privileges of the user invoking
the program. (CVE-2017-2820)

Jiaqi Peng discovered that the poppler pdfunite tool incorrectly
parsed certain malformed PDF documents. If a user or automated system
were tricked into opening a crafted PDF file, an attacker could cause
poppler to crash, resulting in a denial of service. (CVE-2017-7511)

It was discovered that the poppler pdfunite tool incorrectly parsed
certain malformed PDF documents. If a user or automated system were
tricked into opening a crafted PDF file, an attacker could cause
poppler to hang, resulting in a denial of service. (CVE-2017-7515)

It was discovered that poppler incorrectly handled JPEG 2000 images.
If a user or automated system were tricked into opening a crafted PDF
file, an attacker could cause cause poppler to crash, resulting in a
denial of service. (CVE-2017-9083)

It was discovered that poppler incorrectly handled memory when
processing PDF documents. If a user or automated system were tricked
into opening a crafted PDF file, an attacker could cause poppler to
consume resources, resulting in a denial of service. (CVE-2017-9406,
CVE-2017-9408)

Alberto Garcia, Francisco Oca, and Suleman Ali discovered that the
poppler pdftocairo tool incorrectly parsed certain malformed PDF
documents. If a user or automated system were tricked into opening a
crafted PDF file, an attacker could cause poppler to crash, resulting
in a denial of service. (CVE-2017-9775).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3350-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-cpp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-cpp0v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-glib8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt4-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt5-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler44");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler61");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/10");
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

if (ubuntu_check(osver:"14.04", pkgname:"libpoppler-cpp0", pkgver:"0.24.5-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libpoppler-glib8", pkgver:"0.24.5-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libpoppler-qt4-4", pkgver:"0.24.5-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libpoppler-qt5-1", pkgver:"0.24.5-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libpoppler44", pkgver:"0.24.5-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"poppler-utils", pkgver:"0.24.5-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libpoppler-cpp0", pkgver:"0.41.0-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libpoppler-glib8", pkgver:"0.41.0-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libpoppler-qt4-4", pkgver:"0.41.0-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libpoppler-qt5-1", pkgver:"0.41.0-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libpoppler58", pkgver:"0.41.0-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"poppler-utils", pkgver:"0.41.0-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libpoppler-cpp0v5", pkgver:"0.44.0-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libpoppler-glib8", pkgver:"0.44.0-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libpoppler-qt4-4", pkgver:"0.44.0-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libpoppler-qt5-1", pkgver:"0.44.0-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libpoppler61", pkgver:"0.44.0-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"poppler-utils", pkgver:"0.44.0-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"libpoppler-cpp0v5", pkgver:"0.48.0-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"libpoppler-glib8", pkgver:"0.48.0-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"libpoppler-qt4-4", pkgver:"0.48.0-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"libpoppler-qt5-1", pkgver:"0.48.0-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"libpoppler64", pkgver:"0.48.0-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"poppler-utils", pkgver:"0.48.0-2ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpoppler-cpp0 / libpoppler-cpp0v5 / libpoppler-glib8 / etc");
}
