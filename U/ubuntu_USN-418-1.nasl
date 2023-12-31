#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-418-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(28010);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2007-0493", "CVE-2007-0494");
  script_bugtraq_id(22229, 22231);
  script_xref(name:"USN", value:"418-1");

  script_name(english:"Ubuntu 5.10 / 6.06 LTS / 6.10 : bind9 vulnerabilities (USN-418-1)");
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
"A flaw was discovered in Bind's DNSSEC validation code. Remote
attackers could send a specially crafted DNS query which would cause
the Bind server to crash, resulting in a denial of service. Only
servers configured to use DNSSEC extensions were vulnerable.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/418-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind9-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblwres1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblwres9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lwresd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2019 Canonical, Inc. / NASL script (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^(5\.10|6\.06|6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.10 / 6.06 / 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.10", pkgname:"bind9", pkgver:"9.3.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"bind9-doc", pkgver:"9.3.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"bind9-host", pkgver:"9.3.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"dnsutils", pkgver:"9.3.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libbind-dev", pkgver:"9.3.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libbind9-0", pkgver:"9.3.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libdns20", pkgver:"1:9.3.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libisc9", pkgver:"9.3.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libisccc0", pkgver:"9.3.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libisccfg1", pkgver:"9.3.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"liblwres1", pkgver:"9.3.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"lwresd", pkgver:"9.3.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"bind9", pkgver:"9.3.2-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"bind9-doc", pkgver:"9.3.2-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"bind9-host", pkgver:"9.3.2-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dnsutils", pkgver:"9.3.2-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libbind-dev", pkgver:"9.3.2-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libbind9-0", pkgver:"9.3.2-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdns21", pkgver:"1:9.3.2-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libisc11", pkgver:"9.3.2-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libisccc0", pkgver:"9.3.2-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libisccfg1", pkgver:"9.3.2-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"liblwres9", pkgver:"9.3.2-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"lwresd", pkgver:"9.3.2-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"bind9", pkgver:"9.3.2-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"bind9-doc", pkgver:"9.3.2-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"bind9-host", pkgver:"9.3.2-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"dnsutils", pkgver:"9.3.2-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libbind-dev", pkgver:"9.3.2-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libbind9-0", pkgver:"9.3.2-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libdns21", pkgver:"1:9.3.2-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libisc11", pkgver:"9.3.2-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libisccc0", pkgver:"9.3.2-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libisccfg1", pkgver:"9.3.2-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"liblwres9", pkgver:"9.3.2-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"lwresd", pkgver:"9.3.2-2ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind9 / bind9-doc / bind9-host / dnsutils / libbind-dev / etc");
}
