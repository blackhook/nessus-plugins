#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3583-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107003);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2017-0750", "CVE-2017-0861", "CVE-2017-1000407", "CVE-2017-12153", "CVE-2017-12190", "CVE-2017-12192", "CVE-2017-14051", "CVE-2017-14140", "CVE-2017-14156", "CVE-2017-14489", "CVE-2017-15102", "CVE-2017-15115", "CVE-2017-15274", "CVE-2017-15868", "CVE-2017-16525", "CVE-2017-17450", "CVE-2017-17806", "CVE-2017-18017", "CVE-2017-5669", "CVE-2017-5754", "CVE-2017-7542", "CVE-2017-7889", "CVE-2017-8824", "CVE-2018-5333", "CVE-2018-5344");
  script_xref(name:"USN", value:"3583-1");
  script_xref(name:"IAVA", value:"2018-A-0019");

  script_name(english:"Ubuntu 14.04 LTS : linux vulnerabilities (USN-3583-1) (Meltdown)");
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
"It was discovered that an out-of-bounds write vulnerability existed in
the Flash-Friendly File System (f2fs) in the Linux kernel. An attacker
could construct a malicious file system that, when mounted, could
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-0750)

It was discovered that a race condition leading to a use-after-free
vulnerability existed in the ALSA PCM subsystem of the Linux kernel. A
local attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2017-0861)

It was discovered that the KVM implementation in the Linux kernel
allowed passthrough of the diagnostic I/O port 0x80. An attacker in a
guest VM could use this to cause a denial of service (system crash) in
the host OS. (CVE-2017-1000407)

Bo Zhang discovered that the netlink wireless configuration interface
in the Linux kernel did not properly validate attributes when handling
certain requests. A local attacker with the CAP_NET_ADMIN could use
this to cause a denial of service (system crash). (CVE-2017-12153)

Vitaly Mayatskikh discovered that the SCSI subsystem in the Linux
kernel did not properly track reference counts when merging buffers. A
local attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2017-12190)

It was discovered that the key management subsystem in the Linux
kernel did not properly restrict key reads on negatively instantiated
keys. A local attacker could use this to cause a denial of service
(system crash). (CVE-2017-12192)

It was discovered that an integer overflow existed in the sysfs
interface for the QLogic 24xx+ series SCSI driver in the Linux kernel.
A local privileged attacker could use this to cause a denial of
service (system crash). (CVE-2017-14051)

Otto Ebeling discovered that the memory manager in the Linux kernel
did not properly check the effective UID in some situations. A local
attacker could use this to expose sensitive information.
(CVE-2017-14140)

It was discovered that the ATI Radeon framebuffer driver in the Linux
kernel did not properly initialize a data structure returned to user
space. A local attacker could use this to expose sensitive information
(kernel memory). (CVE-2017-14156)

ChunYu Wang discovered that the iSCSI transport implementation in the
Linux kernel did not properly validate data structures. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2017-14489)

James Patrick-Evans discovered a race condition in the LEGO USB
Infrared Tower driver in the Linux kernel. A physically proximate
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-15102)

ChunYu Wang discovered that a use-after-free vulnerability existed in
the SCTP protocol implementation in the Linux kernel. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code, (CVE-2017-15115)

It was discovered that the key management subsystem in the Linux
kernel did not properly handle NULL payloads with non-zero length
values. A local attacker could use this to cause a denial of service
(system crash). (CVE-2017-15274)

It was discovered that the Bluebooth Network Encapsulation Protocol
(BNEP) implementation in the Linux kernel did not validate the type of
socket passed in the BNEPCONNADD ioctl(). A local attacker with the
CAP_NET_ADMIN privilege could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2017-15868)

Andrey Konovalov discovered a use-after-free vulnerability in the USB
serial console driver in the Linux kernel. A physically proximate
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-16525)

It was discovered that the netfilter passive OS fingerprinting
(xt_osf) module did not properly perform access control checks. A
local attacker could improperly modify the systemwide OS fingerprint
list. (CVE-2017-17450)

It was discovered that the HMAC implementation did not validate the
state of the underlying cryptographic hash algorithm. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2017-17806)

Denys Fedoryshchenko discovered a use-after-free vulnerability in the
netfilter xt_TCPMSS filter of the Linux kernel. A remote attacker
could use this to cause a denial of service (system crash).
(CVE-2017-18017)

Gareth Evans discovered that the shm IPC subsystem in the Linux kernel
did not properly restrict mapping page zero. A local privileged
attacker could use this to execute arbitrary code. (CVE-2017-5669)

It was discovered that an integer overflow vulnerability existing in
the IPv6 implementation in the Linux kernel. A local attacker could
use this to cause a denial of service (infinite loop). (CVE-2017-7542)

Tommi Rantala and Brad Spengler discovered that the memory manager in
the Linux kernel did not properly enforce the CONFIG_STRICT_DEVMEM
protection mechanism. A local attacker with access to /dev/mem could
use this to expose sensitive information or possibly execute arbitrary
code. (CVE-2017-7889)

Mohamed Ghannam discovered a use-after-free vulnerability in the DCCP
protocol implementation in the Linux kernel. A local attacker could
use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2017-8824)

Mohamed Ghannam discovered a NULL pointer dereference in the RDS
(Reliable Datagram Sockets) protocol implementation of the Linux
kernel. A local attacker could use this to cause a denial of service
(system crash). (CVE-2018-5333)

Fan Long Fei  discovered that a race condition existed in loop block
device implementation in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2018-5344)

USN-3524-1 mitigated CVE-2017-5754 (Meltdown) for the amd64
architecture in Ubuntu 14.04 LTS. This update provides the
corresponding mitigations for the ppc64el architecture. Original
advisory details :

Jann Horn discovered that microprocessors utilizing speculative
execution and indirect branch prediction may allow unauthorized memory
reads via sidechannel attacks. This flaw is known as Meltdown. A local
attacker could use this to expose sensitive information, including
kernel memory. (CVE-2017-5754).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3583-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Reliable Datagram Sockets (RDS) rds_atomic_free_op NULL pointer dereference Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/26");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2018-2023 Canonical, Inc. / NASL script (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("ksplice.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2017-0750", "CVE-2017-0861", "CVE-2017-1000407", "CVE-2017-12153", "CVE-2017-12190", "CVE-2017-12192", "CVE-2017-14051", "CVE-2017-14140", "CVE-2017-14156", "CVE-2017-14489", "CVE-2017-15102", "CVE-2017-15115", "CVE-2017-15274", "CVE-2017-15868", "CVE-2017-16525", "CVE-2017-17450", "CVE-2017-17806", "CVE-2017-18017", "CVE-2017-5669", "CVE-2017-5754", "CVE-2017-7542", "CVE-2017-7889", "CVE-2017-8824", "CVE-2018-5333", "CVE-2018-5344");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3583-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-142-generic", pkgver:"3.13.0-142.191")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-142-generic-lpae", pkgver:"3.13.0-142.191")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-142-lowlatency", pkgver:"3.13.0-142.191")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic", pkgver:"3.13.0.142.152")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic-lpae", pkgver:"3.13.0.142.152")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-lowlatency", pkgver:"3.13.0.142.152")) flag++;

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
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.13-generic / linux-image-3.13-generic-lpae / etc");
}
