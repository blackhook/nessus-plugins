#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-900-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44640);
  script_version("1.16");
  script_cvs_date("Date: 2019/09/19 12:54:26");

  script_cve_id("CVE-2009-1904", "CVE-2009-4124", "CVE-2009-4492");
  script_bugtraq_id(35278, 37710);
  script_xref(name:"USN", value:"900-1");

  script_name(english:"Ubuntu 8.10 / 9.04 / 9.10 : ruby1.9 vulnerabilities (USN-900-1)");
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
"Emmanouel Kellinis discovered that Ruby did not properly handle
certain string operations. An attacker could exploit this issue and
possibly execute arbitrary code with application privileges.
(CVE-2009-4124)

Giovanni Pellerano, Alessandro Tanasi, and Francesco Ongaro discovered
that Ruby did not properly sanitize data written to log files. An
attacker could insert specially crafted data into log files which
could affect certain terminal emulators and cause arbitrary files to
be overwritten, or even possibly execute arbitrary commands.
(CVE-2009-4492)

It was discovered that Ruby did not properly handle string arguments
that represent large numbers. An attacker could exploit this and cause
a denial of service. This issue only affected Ubuntu 9.10.
(CVE-2009-1904).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/900-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:irb1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbm-ruby1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgdbm-ruby1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenssl-ruby1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreadline-ruby1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby1.9-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtcltk-ruby1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rdoc1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ri1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9-elisp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9-examples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/17");
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
if (! preg(pattern:"^(8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.10", pkgname:"irb1.9", pkgver:"1.9.0.2-7ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libdbm-ruby1.9", pkgver:"1.9.0.2-7ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgdbm-ruby1.9", pkgver:"1.9.0.2-7ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libopenssl-ruby1.9", pkgver:"1.9.0.2-7ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libreadline-ruby1.9", pkgver:"1.9.0.2-7ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libruby1.9", pkgver:"1.9.0.2-7ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libruby1.9-dbg", pkgver:"1.9.0.2-7ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libtcltk-ruby1.9", pkgver:"1.9.0.2-7ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"rdoc1.9", pkgver:"1.9.0.2-7ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ri1.9", pkgver:"1.9.0.2-7ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ruby1.9", pkgver:"1.9.0.2-7ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ruby1.9-dev", pkgver:"1.9.0.2-7ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ruby1.9-elisp", pkgver:"1.9.0.2-7ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ruby1.9-examples", pkgver:"1.9.0.2-7ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"irb1.9", pkgver:"1.9.0.2-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libdbm-ruby1.9", pkgver:"1.9.0.2-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libgdbm-ruby1.9", pkgver:"1.9.0.2-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libopenssl-ruby1.9", pkgver:"1.9.0.2-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libreadline-ruby1.9", pkgver:"1.9.0.2-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libruby1.9", pkgver:"1.9.0.2-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libruby1.9-dbg", pkgver:"1.9.0.2-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libtcltk-ruby1.9", pkgver:"1.9.0.2-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"rdoc1.9", pkgver:"1.9.0.2-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ri1.9", pkgver:"1.9.0.2-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ruby1.9", pkgver:"1.9.0.2-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ruby1.9-dev", pkgver:"1.9.0.2-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ruby1.9-elisp", pkgver:"1.9.0.2-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ruby1.9-examples", pkgver:"1.9.0.2-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"irb1.9", pkgver:"1.9.0.5-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libdbm-ruby1.9", pkgver:"1.9.0.5-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgdbm-ruby1.9", pkgver:"1.9.0.5-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libopenssl-ruby1.9", pkgver:"1.9.0.5-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libreadline-ruby1.9", pkgver:"1.9.0.5-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libruby1.9", pkgver:"1.9.0.5-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libruby1.9-dbg", pkgver:"1.9.0.5-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libtcltk-ruby1.9", pkgver:"1.9.0.5-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"rdoc1.9", pkgver:"1.9.0.5-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ri1.9", pkgver:"1.9.0.5-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ruby1.9", pkgver:"1.9.0.5-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ruby1.9-dev", pkgver:"1.9.0.5-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ruby1.9-elisp", pkgver:"1.9.0.5-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ruby1.9-examples", pkgver:"1.9.0.5-1ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irb1.9 / libdbm-ruby1.9 / libgdbm-ruby1.9 / libopenssl-ruby1.9 / etc");
}
