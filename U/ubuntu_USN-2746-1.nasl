#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2746-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86147);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-1337");
  script_xref(name:"USN", value:"2746-1");

  script_name(english:"Ubuntu 14.04 LTS / 15.04 : simplestreams vulnerability (USN-2746-1)");
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
"It was discovered that Simple Streams did not properly perform gpg
verification in some situations. A remote attacker could use this to
perform a man-in-the-middle attack and inject malicious content into
the stream.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2746-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-simplestreams");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-simplestreams-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-simplestreams");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:simplestreams");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2020 Canonical, Inc. / NASL script (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(14\.04|15\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 15.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"python-simplestreams", pkgver:"0.1.0~bzr341-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python-simplestreams-openstack", pkgver:"0.1.0~bzr341-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python3-simplestreams", pkgver:"0.1.0~bzr341-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"simplestreams", pkgver:"0.1.0~bzr341-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"python-simplestreams", pkgver:"0.1.0~bzr354-0ubuntu1.15.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"python-simplestreams-openstack", pkgver:"0.1.0~bzr354-0ubuntu1.15.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"python3-simplestreams", pkgver:"0.1.0~bzr354-0ubuntu1.15.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"simplestreams", pkgver:"0.1.0~bzr354-0ubuntu1.15.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-simplestreams / python-simplestreams-openstack / etc");
}
