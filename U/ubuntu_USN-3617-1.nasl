#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3617-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108834);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2017-0861", "CVE-2017-1000407", "CVE-2017-15129", "CVE-2017-16532", "CVE-2017-16537", "CVE-2017-16645", "CVE-2017-16646", "CVE-2017-16647", "CVE-2017-16649", "CVE-2017-16650", "CVE-2017-16994", "CVE-2017-17448", "CVE-2017-17450", "CVE-2017-17741", "CVE-2017-17805", "CVE-2017-17806", "CVE-2017-17807", "CVE-2017-18204", "CVE-2018-1000026", "CVE-2018-5332", "CVE-2018-5333", "CVE-2018-5344");
  script_xref(name:"USN", value:"3617-1");

  script_name(english:"Ubuntu 17.10 : linux vulnerabilities (USN-3617-1)");
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
"It was discovered that a race condition leading to a use-after-free
vulnerability existed in the ALSA PCM subsystem of the Linux kernel. A
local attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2017-0861)

It was discovered that the KVM implementation in the Linux kernel
allowed passthrough of the diagnostic I/O port 0x80. An attacker in a
guest VM could use this to cause a denial of service (system crash) in
the host OS. (CVE-2017-1000407)

It was discovered that a use-after-free vulnerability existed in the
network namespaces implementation in the Linux kernel. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-15129)

Andrey Konovalov discovered that the usbtest device driver in the
Linux kernel did not properly validate endpoint metadata. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2017-16532)

Andrey Konovalov discovered that the SoundGraph iMON USB driver in the
Linux kernel did not properly validate device metadata. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2017-16537)

Andrey Konovalov discovered that the IMS Passenger Control Unit USB
driver in the Linux kernel did not properly validate device
descriptors. A physically proximate attacker could use this to cause a
denial of service (system crash). (CVE-2017-16645)

Andrey Konovalov discovered that the DiBcom DiB0700 USB DVB driver in
the Linux kernel did not properly handle detach events. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2017-16646)

Andrey Konovalov discovered that the ASIX Ethernet USB driver in the
Linux kernel did not properly handle suspend and resume events. A
physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2017-16647)

Andrey Konovalov discovered that the CDC USB Ethernet driver did not
properly validate device descriptors. A physically proximate attacker
could use this to cause a denial of service (system crash).
(CVE-2017-16649)

Andrey Konovalov discovered that the QMI WWAN USB driver did not
properly validate device descriptors. A physically proximate attacker
could use this to cause a denial of service (system crash).
(CVE-2017-16650)

It was discovered that the HugeTLB component of the Linux kernel did
not properly handle holes in hugetlb ranges. A local attacker could
use this to expose sensitive information (kernel memory).
(CVE-2017-16994)

It was discovered that the netfilter component of the Linux did not
properly restrict access to the connection tracking helpers list. A
local attacker could use this to bypass intended access restrictions.
(CVE-2017-17448)

It was discovered that the netfilter passive OS fingerprinting
(xt_osf) module did not properly perform access control checks. A
local attacker could improperly modify the system-wide OS fingerprint
list. (CVE-2017-17450)

Dmitry Vyukov discovered that the KVM implementation in the Linux
kernel contained an out-of-bounds read when handling memory-mapped
I/O. A local attacker could use this to expose sensitive information.
(CVE-2017-17741)

It was discovered that the Salsa20 encryption algorithm
implementations in the Linux kernel did not properly handle
zero-length inputs. A local attacker could use this to cause a denial
of service (system crash). (CVE-2017-17805)

It was discovered that the HMAC implementation did not validate the
state of the underlying cryptographic hash algorithm. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2017-17806)

It was discovered that the keyring implementation in the Linux kernel
did not properly check permissions when a key request was performed on
a tasks' default keyring. A local attacker could use this to add keys
to unauthorized keyrings. (CVE-2017-17807)

It was discovered that a race condition existed in the OCFS2 file
system implementation in the Linux kernel. A local attacker could use
this to cause a denial of service (kernel deadlock). (CVE-2017-18204)

It was discovered that the Broadcom NetXtremeII ethernet driver in the
Linux kernel did not properly validate Generic Segment Offload (GSO)
packet sizes. An attacker could use this to cause a denial of service
(interface unavailability). (CVE-2018-1000026)

It was discovered that the Reliable Datagram Socket (RDS)
implementation in the Linux kernel contained an out-of-bounds during
RDMA page allocation. An attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code.
(CVE-2018-5332)

Mohamed Ghannam discovered a NULL pointer dereference in the RDS
(Reliable Datagram Sockets) protocol implementation of the Linux
kernel. A local attacker could use this to cause a denial of service
(system crash). (CVE-2018-5333)

Fan Long Fei  discovered that a race condition existed in loop block
device implementation in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2018-5344).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3617-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Reliable Datagram Sockets (RDS) rds_atomic_free_op NULL pointer dereference Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(17\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 17.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2017-0861", "CVE-2017-1000407", "CVE-2017-15129", "CVE-2017-16532", "CVE-2017-16537", "CVE-2017-16645", "CVE-2017-16646", "CVE-2017-16647", "CVE-2017-16649", "CVE-2017-16650", "CVE-2017-16994", "CVE-2017-17448", "CVE-2017-17450", "CVE-2017-17741", "CVE-2017-17805", "CVE-2017-17806", "CVE-2017-17807", "CVE-2017-18204", "CVE-2018-1000026", "CVE-2018-5332", "CVE-2018-5333", "CVE-2018-5344");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3617-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"17.10", pkgname:"linux-image-4.13.0-38-generic", pkgver:"4.13.0-38.43")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-4.13.0-38-generic-lpae", pkgver:"4.13.0-38.43")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-4.13.0-38-lowlatency", pkgver:"4.13.0-38.43")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-generic", pkgver:"4.13.0.38.41")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-generic-lpae", pkgver:"4.13.0.38.41")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-lowlatency", pkgver:"4.13.0.38.41")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.13-generic / linux-image-4.13-generic-lpae / etc");
}
