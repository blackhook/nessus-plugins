#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3282-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100265);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2017-8105", "CVE-2017-8287");
  script_xref(name:"USN", value:"3282-2");

  script_name(english:"Ubuntu 12.04 LTS : FreeType vulnerabilities (USN-3282-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that FreeType did not correctly handle certain
malformed font files. If a user were tricked into using a specially
crafted font file, a remote attacker could cause FreeType to crash,
resulting in a denial of service, or possibly execute arbitrary code.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libfreetype6 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreetype6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017-2023 Canonical, Inc. / NASL script (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libfreetype6", pkgver:"2.4.8-1ubuntu2.6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libfreetype6");
}
