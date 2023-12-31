#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1085-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52667);
  script_version("1.8");
  script_cvs_date("Date: 2019/09/19 12:54:26");

  script_cve_id("CVE-2010-2482", "CVE-2010-2595", "CVE-2010-2597", "CVE-2010-2598", "CVE-2010-2630", "CVE-2010-3087", "CVE-2011-0191");
  script_bugtraq_id(41088, 41295, 41475, 41480, 43366, 46657);
  script_xref(name:"USN", value:"1085-2");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : tiff regression (USN-1085-2)");
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
"USN-1085-1 fixed vulnerabilities in the system TIFF library. The
upstream fixes were incomplete and created problems for certain
CCITTFAX4 files. This update fixes the problem.

We apologize for the inconvenience.

Sauli Pahlman discovered that the TIFF library incorrectly handled
invalid td_stripbytecount fields. If a user or automated system were
tricked into opening a specially crafted TIFF image, a remote attacker
could crash the application, leading to a denial of service. This
issue only affected Ubuntu 10.04 LTS and 10.10. (CVE-2010-2482)

Sauli Pahlman discovered that the TIFF library incorrectly
handled TIFF files with an invalid combination of
SamplesPerPixel and Photometric values. If a user or
automated system were tricked into opening a specially
crafted TIFF image, a remote attacker could crash the
application, leading to a denial of service. This issue only
affected Ubuntu 10.10. (CVE-2010-2482)

Nicolae Ghimbovschi discovered that the TIFF library
incorrectly handled invalid ReferenceBlackWhite values. If a
user or automated system were tricked into opening a
specially crafted TIFF image, a remote attacker could crash
the application, leading to a denial of service.
(CVE-2010-2595)

Sauli Pahlman discovered that the TIFF library incorrectly
handled certain default fields. If a user or automated
system were tricked into opening a specially crafted TIFF
image, a remote attacker could crash the application,
leading to a denial of service. (CVE-2010-2597,
CVE-2010-2598)

It was discovered that the TIFF library incorrectly
validated certain data types. If a user or automated system
were tricked into opening a specially crafted TIFF image, a
remote attacker could crash the application, leading to a
denial of service. (CVE-2010-2630)

It was discovered that the TIFF library incorrectly handled
downsampled JPEG data. If a user or automated system were
tricked into opening a specially crafted TIFF image, a
remote attacker could execute arbitrary code with user
privileges, or crash the application, leading to a denial of
service. This issue only affected Ubuntu 10.04 LTS and
10.10. (CVE-2010-3087)

It was discovered that the TIFF library incorrectly handled
certain JPEG data. If a user or automated system were
tricked into opening a specially crafted TIFF image, a
remote attacker could execute arbitrary code with user
privileges, or crash the application, leading to a denial of
service. This issue only affected Ubuntu 6.06 LTS, 8.04 LTS
and 9.10. (CVE-2011-0191)

It was discovered that the TIFF library incorrectly handled
certain TIFF FAX images. If a user or automated system were
tricked into opening a specially crafted TIFF FAX image, a
remote attacker could execute arbitrary code with user
privileges, or crash the application, leading to a denial of
service. (CVE-2011-0191).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1085-2/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiffxx0c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2019 Canonical, Inc. / NASL script (C) 2011-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
release = chomp(release);
if (! preg(pattern:"^(6\.06|8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libtiff-opengl", pkgver:"3.7.4-1ubuntu3.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libtiff-tools", pkgver:"3.7.4-1ubuntu3.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libtiff4", pkgver:"3.7.4-1ubuntu3.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libtiff4-dev", pkgver:"3.7.4-1ubuntu3.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libtiffxx0c2", pkgver:"3.7.4-1ubuntu3.10")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libtiff-opengl", pkgver:"3.8.2-7ubuntu3.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libtiff-tools", pkgver:"3.8.2-7ubuntu3.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libtiff4", pkgver:"3.8.2-7ubuntu3.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libtiff4-dev", pkgver:"3.8.2-7ubuntu3.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libtiffxx0c2", pkgver:"3.8.2-7ubuntu3.8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libtiff-doc", pkgver:"3.8.2-13ubuntu0.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libtiff-opengl", pkgver:"3.8.2-13ubuntu0.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libtiff-tools", pkgver:"3.8.2-13ubuntu0.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libtiff4", pkgver:"3.8.2-13ubuntu0.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libtiff4-dev", pkgver:"3.8.2-13ubuntu0.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libtiffxx0c2", pkgver:"3.8.2-13ubuntu0.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libtiff-doc", pkgver:"3.9.2-2ubuntu0.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libtiff-opengl", pkgver:"3.9.2-2ubuntu0.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libtiff-tools", pkgver:"3.9.2-2ubuntu0.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libtiff4", pkgver:"3.9.2-2ubuntu0.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libtiff4-dev", pkgver:"3.9.2-2ubuntu0.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libtiffxx0c2", pkgver:"3.9.2-2ubuntu0.5")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libtiff-doc", pkgver:"3.9.4-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libtiff-opengl", pkgver:"3.9.4-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libtiff-tools", pkgver:"3.9.4-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libtiff4", pkgver:"3.9.4-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libtiff4-dev", pkgver:"3.9.4-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libtiffxx0c2", pkgver:"3.9.4-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"tiff", pkgver:"3.9.4-2ubuntu0.2")) flag++;

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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff-doc / libtiff-opengl / libtiff-tools / libtiff4 / etc");
}
