#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-787-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(39371);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2009-0023", "CVE-2009-1191", "CVE-2009-1195", "CVE-2009-1955", "CVE-2009-1956");
  script_bugtraq_id(34663, 35115, 35221, 35251, 35253);
  script_xref(name:"USN", value:"787-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : apache2 vulnerabilities (USN-787-1)");
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
"Matthew Palmer discovered an underflow flaw in apr-util as included in
Apache. An attacker could cause a denial of service via application
crash in Apache using a crafted SVNMasterURI directive, .htaccess
file, or when using mod_apreq2. This issue only affected Ubuntu 6.06
LTS. (CVE-2009-0023)

Sander de Boer discovered that mod_proxy_ajp would reuse connections
when a client closed a connection without sending a request body. A
remote attacker could exploit this to obtain sensitive response data.
This issue only affected Ubuntu 9.04. (CVE-2009-1191)

Jonathan Peatfield discovered that Apache did not process Includes
options correctly. With certain configurations of Options and
AllowOverride, a local attacker could use an .htaccess file to
override intended restrictions and execute arbitrary code via a
Server-Side-Include file. This issue affected Ubuntu 8.04 LTS, 8.10
and 9.04. (CVE-2009-1195)

It was discovered that the XML parser did not properly handle entity
expansion. A remote attacker could cause a denial of service via
memory resource consumption by sending a crafted request to an Apache
server configured to use mod_dav or mod_dav_svn. This issue only
affected Ubuntu 6.06 LTS. (CVE-2009-1955)

C. Michael Pilato discovered an off-by-one buffer overflow in apr-util
when formatting certain strings. For big-endian machines (powerpc,
hppa and sparc in Ubuntu), a remote attacker could cause a denial of
service or information disclosure leak. All other architectures for
Ubuntu are not considered to be at risk. This issue only affected
Ubuntu 6.06 LTS. (CVE-2009-1956).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/787-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-perchild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-prefork-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-threaded-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2.2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapr0-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2019 Canonical, Inc. / NASL script (C) 2009-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"apache2", pkgver:"2.0.55-4ubuntu2.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-common", pkgver:"2.0.55-4ubuntu2.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-doc", pkgver:"2.0.55-4ubuntu2.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-mpm-perchild", pkgver:"2.0.55-4ubuntu2.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-mpm-prefork", pkgver:"2.0.55-4ubuntu2.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-mpm-worker", pkgver:"2.0.55-4ubuntu2.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-prefork-dev", pkgver:"2.0.55-4ubuntu2.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-threaded-dev", pkgver:"2.0.55-4ubuntu2.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-utils", pkgver:"2.0.55-4ubuntu2.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libapr0", pkgver:"2.0.55-4ubuntu2.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libapr0-dev", pkgver:"2.0.55-4ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2", pkgver:"2.2.8-1ubuntu0.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-doc", pkgver:"2.2.8-1ubuntu0.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-mpm-event", pkgver:"2.2.8-1ubuntu0.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-mpm-perchild", pkgver:"2.2.8-1ubuntu0.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-mpm-prefork", pkgver:"2.2.8-1ubuntu0.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-mpm-worker", pkgver:"2.2.8-1ubuntu0.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-prefork-dev", pkgver:"2.2.8-1ubuntu0.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-src", pkgver:"2.2.8-1ubuntu0.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-threaded-dev", pkgver:"2.2.8-1ubuntu0.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-utils", pkgver:"2.2.8-1ubuntu0.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2.2-common", pkgver:"2.2.8-1ubuntu0.8")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apache2", pkgver:"2.2.9-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apache2-doc", pkgver:"2.2.9-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apache2-mpm-event", pkgver:"2.2.9-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apache2-mpm-prefork", pkgver:"2.2.9-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apache2-mpm-worker", pkgver:"2.2.9-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apache2-prefork-dev", pkgver:"2.2.9-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apache2-src", pkgver:"2.2.9-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apache2-suexec", pkgver:"2.2.9-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apache2-suexec-custom", pkgver:"2.2.9-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apache2-threaded-dev", pkgver:"2.2.9-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apache2-utils", pkgver:"2.2.9-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apache2.2-common", pkgver:"2.2.9-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2", pkgver:"2.2.11-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-doc", pkgver:"2.2.11-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-mpm-event", pkgver:"2.2.11-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-mpm-prefork", pkgver:"2.2.11-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-mpm-worker", pkgver:"2.2.11-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-prefork-dev", pkgver:"2.2.11-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-src", pkgver:"2.2.11-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-suexec", pkgver:"2.2.11-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-suexec-custom", pkgver:"2.2.11-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-threaded-dev", pkgver:"2.2.11-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-utils", pkgver:"2.2.11-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2.2-common", pkgver:"2.2.11-2ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-common / apache2-doc / apache2-mpm-event / etc");
}
