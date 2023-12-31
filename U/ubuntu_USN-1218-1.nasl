#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1218-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56343);
  script_version("1.14");
  script_cvs_date("Date: 2019/09/19 12:54:27");

  script_cve_id("CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4251", "CVE-2010-4805", "CVE-2011-1020", "CVE-2011-1493", "CVE-2011-1577", "CVE-2011-1585", "CVE-2011-1767", "CVE-2011-1768", "CVE-2011-2182", "CVE-2011-2183", "CVE-2011-2213", "CVE-2011-2484", "CVE-2011-2492", "CVE-2011-2700", "CVE-2011-2723", "CVE-2011-2909", "CVE-2011-2918", "CVE-2011-3637", "CVE-2011-4914");
  script_bugtraq_id(45059, 46567, 46637, 46935, 47343, 48383, 48441);
  script_xref(name:"USN", value:"1218-1");

  script_name(english:"Ubuntu 10.04 LTS : linux vulnerabilities (USN-1218-1)");
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
"Dan Rosenberg discovered that multiple terminal ioctls did not
correctly initialize structure memory. A local attacker could exploit
this to read portions of kernel stack memory, leading to a loss of
privacy. (CVE-2010-4076, CVE-2010-4077)

Alex Shi and Eric Dumazet discovered that the network stack did not
correctly handle packet backlogs. A remote attacker could exploit this
by sending a large amount of network traffic to cause the system to
run out of memory, leading to a denial of service. (CVE-2010-4251,
CVE-2010-4805)

It was discovered that the /proc filesystem did not correctly handle
permission changes when programs executed. A local attacker could hold
open files to examine details about programs running with higher
privileges, potentially increasing the chances of exploiting
additional vulnerabilities. (CVE-2011-1020)

Dan Rosenberg discovered that the X.25 Rose network stack did not
correctly handle certain fields. If a system was running with Rose
enabled, a remote attacker could send specially crafted traffic to
gain root privileges. (CVE-2011-1493)

Timo Warns discovered that the GUID partition parsing routines did not
correctly validate certain structures. A local attacker with physical
access could plug in a specially crafted block device to crash the
system, leading to a denial of service. (CVE-2011-1577)

It was discovered that CIFS incorrectly handled authentication. When a
user had a CIFS share mounted that required authentication, a local
user could mount the same share without knowing the correct password.
(CVE-2011-1585)

It was discovered that the GRE protocol incorrectly handled netns
initialization. A remote attacker could send a packet while the ip_gre
module was loading, and crash the system, leading to a denial of
service. (CVE-2011-1767)

It was discovered that the IP/IP protocol incorrectly handled netns
initialization. A remote attacker could send a packet while the ipip
module was loading, and crash the system, leading to a denial of
service. (CVE-2011-1768)

Ben Hutchings reported a flaw in the kernel's handling of corrupt LDM
partitions. A local user could exploit this to cause a denial of
service or escalate privileges. (CVE-2011-2182)

Andrea Righi discovered a race condition in the KSM memory merging
support. If KSM was being used, a local attacker could exploit this to
crash the system, leading to a denial of service. (CVE-2011-2183)

Dan Rosenberg discovered that the IPv4 diagnostic routines did not
correctly validate certain requests. A local attacker could exploit
this to consume CPU resources, leading to a denial of service.
(CVE-2011-2213)

Vasiliy Kulikov discovered that taskstats listeners were not correctly
handled. A local attacker could exploit this to exhaust memory and CPU
resources, leading to a denial of service. (CVE-2011-2484)

It was discovered that Bluetooth l2cap and rfcomm did not correctly
initialize structures. A local attacker could exploit this to read
portions of the kernel stack, leading to a loss of privacy.
(CVE-2011-2492)

Mauro Carvalho Chehab discovered that the si4713 radio driver did not
correctly check the length of memory copies. If this hardware was
available, a local attacker could exploit this to crash the system or
gain root privileges. (CVE-2011-2700)

Herbert Xu discovered that certain fields were incorrectly handled
when Generic Receive Offload (CVE-2011-2723)

Vasiliy Kulikov discovered that the Comedi driver did not correctly
clear memory. A local attacker could exploit this to read kernel stack
memory, leading to a loss of privacy. (CVE-2011-2909)

The performance counter subsystem did not correctly handle certain
counters. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2011-2918)

A flaw was found in the Linux kernel's /proc/*/*map* interface. A
local, unprivileged user could exploit this flaw to cause a denial of
service. (CVE-2011-3637)

Ben Hutchings discovered several flaws in the Linux Rose (X.25 PLP)
layer. A local user or a remote user on an X.25 network could exploit
these flaws to execute arbitrary code as root. (CVE-2011-4914).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1218-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/30");
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
if (! preg(pattern:"^(10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4251", "CVE-2010-4805", "CVE-2011-1020", "CVE-2011-1493", "CVE-2011-1577", "CVE-2011-1585", "CVE-2011-1767", "CVE-2011-1768", "CVE-2011-2182", "CVE-2011-2183", "CVE-2011-2213", "CVE-2011-2484", "CVE-2011-2492", "CVE-2011-2700", "CVE-2011-2723", "CVE-2011-2909", "CVE-2011-2918", "CVE-2011-3637", "CVE-2011-4914");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-1218-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-34-386", pkgver:"2.6.32-34.77")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-34-generic", pkgver:"2.6.32-34.77")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-34-generic-pae", pkgver:"2.6.32-34.77")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-34-lpia", pkgver:"2.6.32-34.77")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-34-preempt", pkgver:"2.6.32-34.77")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-34-server", pkgver:"2.6.32-34.77")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-34-versatile", pkgver:"2.6.32-34.77")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-34-virtual", pkgver:"2.6.32-34.77")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-2.6-386 / linux-image-2.6-generic / etc");
}
