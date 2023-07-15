#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3805-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118591);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-16839", "CVE-2018-16840", "CVE-2018-16842");
  script_xref(name:"USN", value:"3805-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 18.10 : curl vulnerabilities (USN-3805-1)");
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
"Harry Sintonen discovered that curl incorrectly handled SASL
authentication. A remote attacker could use this issue to cause curl
to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2018-16839)

Brian Carpenter discovered that curl incorrectly handled memory when
closing certain handles. A remote attacker could use this issue to
cause curl to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2018-16840)

Brian Carpenter discovered that the curl command-line tool incorrectly
handled error messages. A remote attacker could possibly use this
issue to obtain sensitive information. (CVE-2018-16842).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3805-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16840");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2018-2023 Canonical, Inc. / NASL script (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(14\.04|16\.04|18\.04|18\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 18.04 / 18.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"curl", pkgver:"7.35.0-1ubuntu2.19")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libcurl3", pkgver:"7.35.0-1ubuntu2.19")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libcurl3-gnutls", pkgver:"7.35.0-1ubuntu2.19")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libcurl3-nss", pkgver:"7.35.0-1ubuntu2.19")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"curl", pkgver:"7.47.0-1ubuntu2.11")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libcurl3", pkgver:"7.47.0-1ubuntu2.11")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libcurl3-gnutls", pkgver:"7.47.0-1ubuntu2.11")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libcurl3-nss", pkgver:"7.47.0-1ubuntu2.11")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"curl", pkgver:"7.58.0-2ubuntu3.5")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libcurl3-gnutls", pkgver:"7.58.0-2ubuntu3.5")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libcurl3-nss", pkgver:"7.58.0-2ubuntu3.5")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libcurl4", pkgver:"7.58.0-2ubuntu3.5")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"curl", pkgver:"7.61.0-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libcurl3-gnutls", pkgver:"7.61.0-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libcurl3-nss", pkgver:"7.61.0-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libcurl4", pkgver:"7.61.0-1ubuntu2.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / libcurl3 / libcurl3-gnutls / libcurl3-nss / libcurl4");
}
