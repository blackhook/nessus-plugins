#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1193-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55923);
  script_version("1.11");
  script_cvs_date("Date: 2019/09/19 12:54:27");

  script_cve_id("CVE-2011-1577", "CVE-2011-1581", "CVE-2011-2182", "CVE-2011-2484", "CVE-2011-2493", "CVE-2011-3619", "CVE-2011-4087", "CVE-2011-4326");
  script_bugtraq_id(47343, 47926, 48383);
  script_xref(name:"USN", value:"1193-1");

  script_name(english:"Ubuntu 11.04 : linux vulnerabilities (USN-1193-1)");
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
"Timo Warns discovered that the GUID partition parsing routines did not
correctly validate certain structures. A local attacker with physical
access could plug in a specially crafted block device to crash the
system, leading to a denial of service. (CVE-2011-1577)

Phil Oester discovered that the network bonding system did not
correctly handle large queues. On some systems, a remote attacker
could send specially crafted traffic to crash the system, leading to a
denial of service. (CVE-2011-1581)

Ben Hutchings reported a flaw in the kernel's handling of corrupt LDM
partitions. A local user could exploit this to cause a denial of
service or escalate privileges. (CVE-2011-2182)

Vasiliy Kulikov discovered that taskstats listeners were not correctly
handled. A local attacker could exploit this to exhaust memory and CPU
resources, leading to a denial of service. (CVE-2011-2484)

Sami Liedes discovered that ext4 did not correctly handle missing root
inodes. A local attacker could trigger the mount of a specially
crafted filesystem to cause the system to crash, leading to a denial
of service. (CVE-2011-2493)

A flaw was discovered in the Linux kernel's AppArmor security
interface when invalid information was written to it. An unprivileged
local user could use this to cause a denial of service on the system.
(CVE-2011-3619)

Scot Doyle discovered that the bridge networking interface incorrectly
handled certain network packets. A remote attacker could exploit this
to crash the system, leading to a denial of service. (CVE-2011-4087)

A bug was found in the way headroom check was performed in
udp6_ufo_fragment() function. A remote attacker could use this flaw to
crash the system. (CVE-2011-4326).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1193-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2019 Canonical, Inc. / NASL script (C) 2011-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2011-1577", "CVE-2011-1581", "CVE-2011-2182", "CVE-2011-2484", "CVE-2011-2493", "CVE-2011-3619", "CVE-2011-4087", "CVE-2011-4326");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-1193-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-11-generic", pkgver:"2.6.38-11.48")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-11-generic-pae", pkgver:"2.6.38-11.48")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-11-server", pkgver:"2.6.38-11.48")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-11-versatile", pkgver:"2.6.38-11.48")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-11-virtual", pkgver:"2.6.38-11.48")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-2.6-generic / linux-image-2.6-generic-pae / etc");
}
