#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1096-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53220);
  script_version("1.10");
  script_cvs_date("Date: 2019/09/19 12:54:26");

  script_cve_id("CVE-2011-0715");
  script_bugtraq_id(46734);
  script_xref(name:"USN", value:"1096-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : subversion vulnerability (USN-1096-1)");
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
"Philip Martin discovered that the Subversion mod_dav_svn module for
Apache did not properly handle certain requests containing a lock
token. A remote attacker could use this flaw to cause the service to
crash, leading to a denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1096-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-core-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-subversion-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/11");
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
if (! preg(pattern:"^(6\.06|8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libapache2-svn", pkgver:"1.3.1-3ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsvn-core-perl", pkgver:"1.3.1-3ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsvn-doc", pkgver:"1.3.1-3ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsvn-javahl", pkgver:"1.3.1-3ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsvn-ruby", pkgver:"1.3.1-3ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsvn-ruby1.8", pkgver:"1.3.1-3ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsvn0", pkgver:"1.3.1-3ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsvn0-dev", pkgver:"1.3.1-3ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python-subversion", pkgver:"1.3.1-3ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-subversion", pkgver:"1.3.1-3ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"subversion", pkgver:"1.3.1-3ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"subversion-tools", pkgver:"1.3.1-3ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libapache2-svn", pkgver:"1.4.6dfsg1-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsvn-dev", pkgver:"1.4.6dfsg1-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsvn-doc", pkgver:"1.4.6dfsg1-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsvn-java", pkgver:"1.4.6dfsg1-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsvn-javahl", pkgver:"1.4.6dfsg1-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsvn-perl", pkgver:"1.4.6dfsg1-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsvn-ruby", pkgver:"1.4.6dfsg1-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsvn-ruby1.8", pkgver:"1.4.6dfsg1-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsvn1", pkgver:"1.4.6dfsg1-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-subversion", pkgver:"1.4.6dfsg1-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-subversion-dbg", pkgver:"1.4.6dfsg1-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"subversion", pkgver:"1.4.6dfsg1-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"subversion-tools", pkgver:"1.4.6dfsg1-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libapache2-svn", pkgver:"1.6.5dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libsvn-dev", pkgver:"1.6.5dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libsvn-doc", pkgver:"1.6.5dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libsvn-java", pkgver:"1.6.5dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libsvn-perl", pkgver:"1.6.5dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libsvn-ruby", pkgver:"1.6.5dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libsvn-ruby1.8", pkgver:"1.6.5dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libsvn1", pkgver:"1.6.5dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-subversion", pkgver:"1.6.5dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-subversion-dbg", pkgver:"1.6.5dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"subversion", pkgver:"1.6.5dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"subversion-tools", pkgver:"1.6.5dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libapache2-svn", pkgver:"1.6.6dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libsvn-dev", pkgver:"1.6.6dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libsvn-doc", pkgver:"1.6.6dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libsvn-java", pkgver:"1.6.6dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libsvn-perl", pkgver:"1.6.6dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libsvn-ruby", pkgver:"1.6.6dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libsvn-ruby1.8", pkgver:"1.6.6dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libsvn1", pkgver:"1.6.6dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"python-subversion", pkgver:"1.6.6dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"python-subversion-dbg", pkgver:"1.6.6dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"subversion", pkgver:"1.6.6dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"subversion-tools", pkgver:"1.6.6dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libapache2-svn", pkgver:"1.6.12dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libsvn-dev", pkgver:"1.6.12dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libsvn-doc", pkgver:"1.6.12dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libsvn-java", pkgver:"1.6.12dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libsvn-perl", pkgver:"1.6.12dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libsvn-ruby", pkgver:"1.6.12dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libsvn-ruby1.8", pkgver:"1.6.12dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libsvn1", pkgver:"1.6.12dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"python-subversion", pkgver:"1.6.12dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"python-subversion-dbg", pkgver:"1.6.12dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"subversion", pkgver:"1.6.12dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"subversion-tools", pkgver:"1.6.12dfsg-1ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-svn / libsvn-core-perl / libsvn-dev / libsvn-doc / etc");
}
