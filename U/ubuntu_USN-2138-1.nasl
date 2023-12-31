#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2138-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72901);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-4579", "CVE-2013-4587", "CVE-2013-6367", "CVE-2013-6368", "CVE-2013-6382", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265", "CVE-2013-7266", "CVE-2013-7267", "CVE-2013-7268", "CVE-2013-7269", "CVE-2013-7270", "CVE-2013-7271", "CVE-2013-7281", "CVE-2014-1438", "CVE-2014-1446", "CVE-2014-1874");
  script_xref(name:"USN", value:"2138-1");

  script_name(english:"Ubuntu 12.10 : linux vulnerabilities (USN-2138-1)");
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
"Mathy Vanhoef discovered an error in the the way the ath9k driver was
handling the BSSID masking. A remote attacker could exploit this error
to discover the original MAC address after a spoofing atack.
(CVE-2013-4579)

Andrew Honig reported a flaw in the Linux Kernel's
kvm_vm_ioctl_create_vcpu function of the Kernel Virtual Machine (KVM)
subsystem. A local user could exploit this flaw to gain privileges on
the host machine. (CVE-2013-4587)

Andrew Honig reported a flaw in the apic_get_tmcct function of the
Kernel Virtual Machine (KVM) subsystem if the Linux kernel. A guest OS
user could exploit this flaw to cause a denial of service or host OS
system crash. (CVE-2013-6367)

Andrew Honig reported an error in the Linux Kernel's Kernel Virtual
Machine (KVM) VAPIC synchronization operation. A local user could
exploit this flaw to gain privileges or cause a denial of service
(system crash). (CVE-2013-6368)

Nico Golde and Fabian Yamaguchi reported buffer underflow errors in
the implementation of the XFS filesystem in the Linux kernel. A local
user with CAP_SYS_ADMIN could exploit these flaw to cause a denial of
service (memory corruption) or possibly other unspecified issues.
(CVE-2013-6382)

mpd reported an information leak in the recvfrom, recvmmsg, and
recvmsg system calls in the Linux kernel. An unprivileged local user
could exploit this flaw to obtain sensitive information from kernel
stack memory. (CVE-2013-7263)

mpb reported an information leak in the Layer Two Tunneling Protocol
(l2tp) of the Linux kernel. A local user could exploit this flaw to
obtain sensitive information from kernel stack memory. (CVE-2013-7264)

mpb reported an information leak in the Phone Network protocol
(phonet) in the Linux kernel. A local user could exploit this flaw to
obtain sensitive information from kernel stack memory. (CVE-2013-7265)

An information leak was discovered in the recvfrom, recvmmsg, and
recvmsg systemcalls when used with ISDN sockets in the Linux kernel. A
local user could exploit this leak to obtain potentially sensitive
information from kernel memory. (CVE-2013-7266)

An information leak was discovered in the recvfrom, recvmmsg, and
recvmsg systemcalls when used with apple talk sockets in the Linux
kernel. A local user could exploit this leak to obtain potentially
sensitive information from kernel memory. (CVE-2013-7267)

An information leak was discovered in the recvfrom, recvmmsg, and
recvmsg systemcalls when used with ipx protocol sockets in the Linux
kernel. A local user could exploit this leak to obtain potentially
sensitive information from kernel memory. (CVE-2013-7268)

An information leak was discovered in the recvfrom, recvmmsg, and
recvmsg systemcalls when used with the netrom address family in the
Linux kernel. A local user could exploit this leak to obtain
potentially sensitive information from kernel memory. (CVE-2013-7269)

An information leak was discovered in the recvfrom, recvmmsg, and
recvmsg systemcalls when used with packet address family sockets in
the Linux kernel. A local user could exploit this leak to obtain
potentially sensitive information from kernel memory. (CVE-2013-7270)

An information leak was discovered in the recvfrom, recvmmsg, and
recvmsg systemcalls when used with x25 protocol sockets in the Linux
kernel. A local user could exploit this leak to obtain potentially
sensitive information from kernel memory. (CVE-2013-7271)

mpb reported an information leak in the Low-Rate Wireless Personal
Area Networks support (IEEE 802.15.4) in the Linux kernel. A local
user could exploit this flaw to obtain sensitive information from
kernel stack memory. (CVE-2013-7281)

halfdog reported an error in the AMD K7 and K8 platform support in the
Linux kernel. An unprivileged local user could exploit this flaw on
AMD based systems to cause a denial of service (task kill) or possibly
gain privileges via a crafted application. (CVE-2014-1438)

An information leak was discovered in the Linux kernel's hamradio YAM
driver for AX.25 packet radio. A local user with the CAP_NET_ADMIN
capability could exploit this flaw to obtain sensitive information
from kernel memory. (CVE-2014-1446)

Matthew Thode reported a denial of service vulnerability in the Linux
kernel when SELinux support is enabled. A local user with the
CAP_MAC_ADMIN capability (and the SELinux mac_admin permission if
running in enforcing mode) could exploit this flaw to cause a denial
of service (kernel crash). (CVE-2014-1874).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2138-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.5-generic and / or
linux-image-3.5-highbank packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.5-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.5-highbank");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2020 Canonical, Inc. / NASL script (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2013-4579", "CVE-2013-4587", "CVE-2013-6367", "CVE-2013-6368", "CVE-2013-6382", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265", "CVE-2013-7266", "CVE-2013-7267", "CVE-2013-7268", "CVE-2013-7269", "CVE-2013-7270", "CVE-2013-7271", "CVE-2013-7281", "CVE-2014-1438", "CVE-2014-1446", "CVE-2014-1874");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-2138-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"12.10", pkgname:"linux-image-3.5.0-47-generic", pkgver:"3.5.0-47.71")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"linux-image-3.5.0-47-highbank", pkgver:"3.5.0-47.71")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.5-generic / linux-image-3.5-highbank");
}
