#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1097-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53221);
  script_version("1.10");
  script_cvs_date("Date: 2019/09/19 12:54:26");

  script_cve_id("CVE-2010-3718", "CVE-2011-0013", "CVE-2011-0534");
  script_bugtraq_id(46164, 46174, 46177);
  script_xref(name:"USN", value:"1097-1");

  script_name(english:"Ubuntu 9.10 / 10.04 LTS / 10.10 : tomcat6 vulnerabilities (USN-1097-1)");
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
"It was discovered that the Tomcat SecurityManager did not properly
restrict the working directory. An attacker could use this flaw to
read or write files outside of the intended working directory.
(CVE-2010-3718)

It was discovered that Tomcat did not properly escape certain
parameters in the Manager application which could result in browsers
becoming vulnerable to cross-site scripting attacks when processing
the output. With cross-site scripting vulnerabilities, if a user were
tricked into viewing server output during a crafted server request, a
remote attacker could exploit this to modify the contents, or steal
confidential data (such as passwords), within the same domain.
(CVE-2011-0013)

It was discovered that Tomcat incorrectly enforced the
maxHttpHeaderSize limit in certain configurations. A remote attacker
could use this flaw to cause Tomcat to consume all available memory,
resulting in a denial of service. (CVE-2011-0534).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1097-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libservlet2.5-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libservlet2.5-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtomcat6-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat6-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat6-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat6-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat6-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat6-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/30");
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
if (! preg(pattern:"^(9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.10", pkgname:"libservlet2.5-java", pkgver:"6.0.20-2ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libservlet2.5-java-doc", pkgver:"6.0.20-2ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libtomcat6-java", pkgver:"6.0.20-2ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"tomcat6", pkgver:"6.0.20-2ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"tomcat6-admin", pkgver:"6.0.20-2ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"tomcat6-common", pkgver:"6.0.20-2ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"tomcat6-docs", pkgver:"6.0.20-2ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"tomcat6-examples", pkgver:"6.0.20-2ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"tomcat6-user", pkgver:"6.0.20-2ubuntu2.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libservlet2.5-java", pkgver:"6.0.24-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libservlet2.5-java-doc", pkgver:"6.0.24-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libtomcat6-java", pkgver:"6.0.24-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"tomcat6", pkgver:"6.0.24-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"tomcat6-admin", pkgver:"6.0.24-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"tomcat6-common", pkgver:"6.0.24-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"tomcat6-docs", pkgver:"6.0.24-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"tomcat6-examples", pkgver:"6.0.24-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"tomcat6-user", pkgver:"6.0.24-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libservlet2.5-java", pkgver:"6.0.28-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libservlet2.5-java-doc", pkgver:"6.0.28-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libtomcat6-java", pkgver:"6.0.28-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"tomcat6", pkgver:"6.0.28-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"tomcat6-admin", pkgver:"6.0.28-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"tomcat6-common", pkgver:"6.0.28-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"tomcat6-docs", pkgver:"6.0.28-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"tomcat6-examples", pkgver:"6.0.28-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"tomcat6-user", pkgver:"6.0.28-2ubuntu1.2")) flag++;

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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libservlet2.5-java / libservlet2.5-java-doc / libtomcat6-java / etc");
}
