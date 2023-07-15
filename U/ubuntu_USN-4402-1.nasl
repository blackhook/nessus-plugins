#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4402-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(137824);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2020-8169", "CVE-2020-8177");
  script_xref(name:"USN", value:"4402-1");
  script_xref(name:"IAVA", value:"2020-A-0291-S");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.10 / 20.04 : curl vulnerabilities (USN-4402-1)");
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
"Marek Szlagor, Gregory Jefferis and Jeroen Ooms discovered that curl
incorrectly handled certain credentials. An attacker could possibly
use this issue to expose sensitive information. This issue only
affected Ubuntu 19.10 and Ubuntu 20.04 LTS. (CVE-2020-8169) It was
discovered that curl incorrectly handled certain parameters. An
attacker could possibly use this issue to overwrite a local file.
(CVE-2020-8177).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4402-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8169");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (! preg(pattern:"^(12\.04|14\.04|16\.04|18\.04|19\.10|20\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 18.04 / 19.10 / 20.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"curl", pkgver:"7.47.0-1ubuntu2.15")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libcurl3", pkgver:"7.47.0-1ubuntu2.15")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libcurl3-gnutls", pkgver:"7.47.0-1ubuntu2.15")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libcurl3-nss", pkgver:"7.47.0-1ubuntu2.15")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"curl", pkgver:"7.58.0-2ubuntu3.9")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libcurl3-gnutls", pkgver:"7.58.0-2ubuntu3.9")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libcurl3-nss", pkgver:"7.58.0-2ubuntu3.9")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libcurl4", pkgver:"7.58.0-2ubuntu3.9")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"curl", pkgver:"7.65.3-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libcurl3-gnutls", pkgver:"7.65.3-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libcurl3-nss", pkgver:"7.65.3-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libcurl4", pkgver:"7.65.3-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"curl", pkgver:"7.68.0-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"libcurl3-gnutls", pkgver:"7.68.0-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"libcurl3-nss", pkgver:"7.68.0-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"libcurl4", pkgver:"7.68.0-1ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / libcurl3 / libcurl3-gnutls / libcurl3-nss / libcurl4");
}
