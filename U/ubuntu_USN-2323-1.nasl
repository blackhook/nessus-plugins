#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2323-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77323);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-3473", "CVE-2014-3474", "CVE-2014-3475", "CVE-2014-3594");
  script_xref(name:"USN", value:"2323-1");

  script_name(english:"Ubuntu 14.04 LTS : horizon vulnerabilities (USN-2323-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jason Hullinger discovered that OpenStack Horizon did not properly
perform input sanitization on Heat templates. If a user were tricked
into using a specially crafted Heat template, an attacker could
conduct cross-site scripting attacks. With cross-site scripting
vulnerabilities, if a user were tricked into viewing server output
during a crafted server request, a remote attacker could exploit this
to modify the contents, or steal confidential data, within the same
domain. (CVE-2014-3473)

Craig Lorentzen discovered that OpenStack Horizon did not properly
perform input sanitization when creating networks. If a user were
tricked into launching an image using the crafted network name, an
attacker could conduct cross-site scripting attacks. (CVE-2014-3474)

Michael Xin discovered that OpenStack Horizon did not properly perform
input sanitization when adding users. If an admin user were tricked
into viewing the users page containing a crafted email address, an
attacker could conduct cross-site scripting attacks. (CVE-2014-3475)

Dennis Felsch and Mario Heiderich discovered that OpenStack Horizon
did not properly perform input sanitization when creating host
aggregates. If an admin user were tricked into viewing the Host
Aggregates page containing a crafted availability zone name, an
attacker could conduct cross-site scripting attacks. (CVE-2014-3594).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2323-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openstack-dashboard package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openstack-dashboard");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/22");
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
if (! preg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"openstack-dashboard", pkgver:"1:2014.1.2-0ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openstack-dashboard");
}
