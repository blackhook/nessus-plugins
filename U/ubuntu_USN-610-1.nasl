#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-610-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(32190);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2008-1293");
  script_xref(name:"USN", value:"610-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 : ltsp vulnerability (USN-610-1)");
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
"Christian Herzog discovered that it was possible to connect to any
LTSP client's X session over the network. A remote attacker could
eavesdrop on X events, read window contents, and record keystrokes,
possibly gaining access to private information.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/610-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ldm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ltsp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ltsp-client-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ltsp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ltsp-server-standalone");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2019 Canonical, Inc. / NASL script (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^(6\.06|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"ldm", pkgver:"0.87.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ltsp-client", pkgver:"0.87.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ltsp-server", pkgver:"0.87.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ltsp-server-standalone", pkgver:"0.87.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ldm", pkgver:"5.0.7.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ltsp-client", pkgver:"5.0.7.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ltsp-server", pkgver:"5.0.7.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ltsp-server-standalone", pkgver:"5.0.7.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ldm", pkgver:"5.0.39.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ltsp-client", pkgver:"5.0.39.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ltsp-client-core", pkgver:"5.0.39.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ltsp-server", pkgver:"5.0.39.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ltsp-server-standalone", pkgver:"5.0.39.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldm / ltsp-client / ltsp-client-core / ltsp-server / etc");
}
