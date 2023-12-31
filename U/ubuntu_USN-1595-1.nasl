#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1595-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62435);
  script_version("1.10");
  script_cvs_date("Date: 2019/09/19 12:54:28");

  script_cve_id("CVE-2011-1202", "CVE-2011-3970", "CVE-2012-2825", "CVE-2012-2870", "CVE-2012-2871", "CVE-2012-2893");
  script_bugtraq_id(47668, 51911, 54203, 55331, 55676);
  script_xref(name:"USN", value:"1595-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : libxslt vulnerabilities (USN-1595-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Evans discovered that libxslt incorrectly handled generate-id
XPath functions. If a user or automated system were tricked into
processing a specially crafted XSLT document, a remote attacker could
obtain potentially sensitive information. This issue only affected
Ubuntu 8.04 LTS, Ubuntu 10.04 LTS and Ubuntu 11.04. (CVE-2011-1202)

It was discovered that libxslt incorrectly parsed certain patterns. If
a user or automated system were tricked into processing a specially
crafted XSLT document, a remote attacker could cause libxslt to crash,
causing a denial of service. (CVE-2011-3970)

Nicholas Gregoire discovered that libxslt incorrectly handled
unexpected DTD nodes. If a user or automated system were tricked into
processing a specially crafted XSLT document, a remote attacker could
cause libxslt to crash, causing a denial of service. (CVE-2012-2825)

Nicholas Gregoire discovered that libxslt incorrectly managed memory.
If a user or automated system were tricked into processing a specially
crafted XSLT document, a remote attacker could cause libxslt to crash,
causing a denial of service. (CVE-2012-2870)

Nicholas Gregoire discovered that libxslt incorrectly handled certain
transforms. If a user or automated system were tricked into processing
a specially crafted XSLT document, a remote attacker could cause
libxslt to crash, causing a denial of service, or possibly execute
arbitrary code. (CVE-2012-2871)

Cris Neckar discovered that libxslt incorrectly managed memory. If a
user or automated system were tricked into processing a specially
crafted XSLT document, a remote attacker could cause libxslt to crash,
causing a denial of service, or possibly execute arbitrary code.
(CVE-2012-2893).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1595-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxslt1.1 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxslt1.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2019 Canonical, Inc. / NASL script (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(8\.04|10\.04|11\.04|11\.10|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 11.04 / 11.10 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libxslt1.1", pkgver:"1.1.22-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libxslt1.1", pkgver:"1.1.26-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libxslt1.1", pkgver:"1.1.26-6ubuntu0.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libxslt1.1", pkgver:"1.1.26-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libxslt1.1", pkgver:"1.1.26-8ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxslt1.1");
}
