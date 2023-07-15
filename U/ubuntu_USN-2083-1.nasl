#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2083-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72005);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-0978", "CVE-2014-1235", "CVE-2014-1236");
  script_bugtraq_id(64674, 64736, 64737);
  script_xref(name:"USN", value:"2083-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 12.10 / 13.04 / 13.10 : graphviz vulnerabilities (USN-2083-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Graphviz incorrectly handled memory in the
yyerror function. If a user were tricked into opening a specially
crafted dot file, an attacker could cause Graphviz to crash, or
possibly execute arbitrary code. (CVE-2014-0978, CVE-2014-1235)

It was discovered that Graphviz incorrectly handled memory in the
chkNum function. If a user were tricked into opening a specially
crafted dot file, an attacker could cause Graphviz to crash, or
possibly execute arbitrary code. (CVE-2014-1236)

The default compiler options for affected releases should reduce the
vulnerability to a denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2083-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected graphviz package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:graphviz");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2020 Canonical, Inc. / NASL script (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(10\.04|12\.04|12\.10|13\.04|13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 12.10 / 13.04 / 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"graphviz", pkgver:"2.20.2-8ubuntu3.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"graphviz", pkgver:"2.26.3-10ubuntu1.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"graphviz", pkgver:"2.26.3-12ubuntu1.1")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"graphviz", pkgver:"2.26.3-14ubuntu1.1")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"graphviz", pkgver:"2.26.3-15ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "graphviz");
}
