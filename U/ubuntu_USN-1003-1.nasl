#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1003-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49805);
  script_version("1.12");
  script_cvs_date("Date: 2019/09/19 12:54:26");

  script_cve_id("CVE-2009-3245", "CVE-2010-2939");
  script_bugtraq_id(38562, 42306);
  script_xref(name:"USN", value:"1003-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.04 / 9.10 / 10.04 LTS / 10.10 : openssl vulnerabilities (USN-1003-1)");
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
"It was discovered that OpenSSL incorrectly handled return codes from
the bn_wexpand function calls. A remote attacker could trigger this
flaw in services that used SSL to cause a denial of service or
possibly execute arbitrary code with application privileges. This
issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 9.04 and 9.10.
(CVE-2009-3245)

It was discovered that OpenSSL incorrectly handled certain private
keys with an invalid prime. A remote attacker could trigger this flaw
in services that used SSL to cause a denial of service or possibly
execute arbitrary code with application privileges. The default
compiler options for affected releases should reduce the vulnerability
to a denial of service. (CVE-2010-2939).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1003-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl0.9.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl0.9.8-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2019 Canonical, Inc. / NASL script (C) 2010-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6\.06|8\.04|9\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libssl-dev", pkgver:"0.9.8a-7ubuntu0.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libssl0.9.8", pkgver:"0.9.8a-7ubuntu0.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libssl0.9.8-dbg", pkgver:"0.9.8a-7ubuntu0.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openssl", pkgver:"0.9.8a-7ubuntu0.13")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libssl-dev", pkgver:"0.9.8g-4ubuntu3.11")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libssl0.9.8", pkgver:"0.9.8g-4ubuntu3.11")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libssl0.9.8-dbg", pkgver:"0.9.8g-4ubuntu3.11")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openssl", pkgver:"0.9.8g-4ubuntu3.11")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openssl-doc", pkgver:"0.9.8g-4ubuntu3.11")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libssl-dev", pkgver:"0.9.8g-15ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libssl0.9.8", pkgver:"0.9.8g-15ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libssl0.9.8-dbg", pkgver:"0.9.8g-15ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openssl", pkgver:"0.9.8g-15ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openssl-doc", pkgver:"0.9.8g-15ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libssl-dev", pkgver:"0.9.8g-16ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libssl0.9.8", pkgver:"0.9.8g-16ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libssl0.9.8-dbg", pkgver:"0.9.8g-16ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openssl", pkgver:"0.9.8g-16ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openssl-doc", pkgver:"0.9.8g-16ubuntu3.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libssl-dev", pkgver:"0.9.8k-7ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libssl0.9.8", pkgver:"0.9.8k-7ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libssl0.9.8-dbg", pkgver:"0.9.8k-7ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openssl", pkgver:"0.9.8k-7ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openssl-doc", pkgver:"0.9.8k-7ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libssl-dev", pkgver:"0.9.8o-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libssl0.9.8", pkgver:"0.9.8o-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libssl0.9.8-dbg", pkgver:"0.9.8o-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openssl", pkgver:"0.9.8o-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openssl-doc", pkgver:"0.9.8o-1ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssl-dev / libssl0.9.8 / libssl0.9.8-dbg / openssl / openssl-doc");
}
