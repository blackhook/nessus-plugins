#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2546-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82073);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-7421", "CVE-2014-9644", "CVE-2015-1421", "CVE-2015-1465");
  script_bugtraq_id(72320, 72322, 72356, 72435);
  script_xref(name:"USN", value:"2546-1");

  script_name(english:"Ubuntu 14.10 : linux vulnerabilities (USN-2546-1)");
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
"A flaw was discovered in the automatic loading of modules in the
crypto subsystem of the Linux kernel. A local user could exploit this
flaw to load installed kernel modules, increasing the attack surface
and potentially using this to gain administrative privileges.
(CVE-2013-7421)

A flaw was discovered in the crypto subsystem when screening module
names for automatic module loading if the name contained a valid
crypto module name, eg. vfat(aes). A local user could exploit this
flaw to load installed kernel modules, increasing the attack surface
and potentially using this to gain administrative privileges.
(CVE-2014-9644)

Sun Baoliang discovered a use after free flaw in the Linux kernel's
SCTP (Stream Control Transmission Protocol) subsystem during INIT
collisions. A remote attacker could exploit this flaw to cause a
denial of service (system crash) or potentially escalate their
privileges on the system. (CVE-2015-1421)

Marcelo Leitner discovered a flaw in the Linux kernel's routing of
packets to too many different dsts/too fast. A remote attacker can
exploit this flaw to cause a denial of service (system crash).
(CVE-2015-1465).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2546-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.16-generic,
linux-image-3.16-generic-lpae and / or linux-image-3.16-lowlatency
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2020 Canonical, Inc. / NASL script (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("ksplice.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(14\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2013-7421", "CVE-2014-9644", "CVE-2015-1421", "CVE-2015-1465");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-2546-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"14.10", pkgname:"linux-image-3.16.0-33-generic", pkgver:"3.16.0-33.44")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"linux-image-3.16.0-33-generic-lpae", pkgver:"3.16.0-33.44")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"linux-image-3.16.0-33-lowlatency", pkgver:"3.16.0-33.44")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.16-generic / linux-image-3.16-generic-lpae / etc");
}
