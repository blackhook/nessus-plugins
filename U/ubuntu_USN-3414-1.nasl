#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3414-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103217);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2017-10664", "CVE-2017-10806", "CVE-2017-10911", "CVE-2017-11434", "CVE-2017-12809", "CVE-2017-7493", "CVE-2017-8112", "CVE-2017-8380", "CVE-2017-9060", "CVE-2017-9310", "CVE-2017-9330", "CVE-2017-9373", "CVE-2017-9374", "CVE-2017-9375", "CVE-2017-9503", "CVE-2017-9524");
  script_xref(name:"USN", value:"3414-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.04 : qemu vulnerabilities (USN-3414-1)");
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
"Leo Gaspard discovered that QEMU incorrectly handled VirtFS access
control. A guest attacker could use this issue to elevate privileges
inside the guest. (CVE-2017-7493)

Li Qiang discovered that QEMU incorrectly handled VMware PVSCSI
emulation. A privileged attacker inside the guest could use this issue
to cause QEMU to consume resources or crash, resulting in a denial of
service. (CVE-2017-8112)

It was discovered that QEMU incorrectly handled MegaRAID SAS 8708EM2
Host Bus Adapter emulation support. A privileged attacker inside the
guest could use this issue to cause QEMU to crash, resulting in a
denial of service, or possibly to obtain sensitive host memory. This
issue only affected Ubuntu 16.04 LTS and Ubuntu 17.04. (CVE-2017-8380)

Li Qiang discovered that QEMU incorrectly handled the Virtio GPU
device. An attacker inside the guest could use this issue to cause
QEMU to consume resources and crash, resulting in a denial of service.
This issue only affected Ubuntu 17.04. (CVE-2017-9060)

Li Qiang discovered that QEMU incorrectly handled the e1000e device. A
privileged attacker inside the guest could use this issue to cause
QEMU to hang, resulting in a denial of service. This issue only
affected Ubuntu 17.04. (CVE-2017-9310)

Li Qiang discovered that QEMU incorrectly handled USB OHCI emulation
support. An attacker inside the guest could use this issue to cause
QEMU to crash, resulting in a denial of service. (CVE-2017-9330)

Li Qiang discovered that QEMU incorrectly handled IDE AHCI emulation
support. A privileged attacker inside the guest could use this issue
to cause QEMU to consume resources and crash, resulting in a denial of
service. (CVE-2017-9373)

Li Qiang discovered that QEMU incorrectly handled USB EHCI emulation
support. A privileged attacker inside the guest could use this issue
to cause QEMU to consume resources and crash, resulting in a denial of
service. (CVE-2017-9374)

Li Qiang discovered that QEMU incorrectly handled USB xHCI emulation
support. A privileged attacker inside the guest could use this issue
to cause QEMU to hang, resulting in a denial of service.
(CVE-2017-9375)

Zhangyanyu discovered that QEMU incorrectly handled MegaRAID SAS
8708EM2 Host Bus Adapter emulation support. A privileged attacker
inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service. (CVE-2017-9503)

It was discovered that the QEMU qemu-nbd server incorrectly handled
initialization. A remote attacker could use this issue to cause the
server to crash, resulting in a denial of service. (CVE-2017-9524)

It was discovered that the QEMU qemu-nbd server incorrectly handled
signals. A remote attacker could use this issue to cause the server to
crash, resulting in a denial of service. (CVE-2017-10664)

Li Qiang discovered that the QEMU USB redirector incorrectly handled
logging debug messages. An attacker inside the guest could use this
issue to cause QEMU to crash, resulting in a denial of service.
(CVE-2017-10806)

Anthony Perard discovered that QEMU incorrectly handled Xen
block-interface responses. An attacker inside the guest could use this
issue to cause QEMU to leak contents of host memory. (CVE-2017-10911)

Reno Robert discovered that QEMU incorrectly handled certain DHCP
options strings. An attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service.
(CVE-2017-11434)

Ryan Salsamendi discovered that QEMU incorrectly handled empty CDROM
device drives. A privileged attacker inside the guest could use this
issue to cause QEMU to crash, resulting in a denial of service. This
issue only affected Ubuntu 16.04 LTS and Ubuntu 17.04.
(CVE-2017-12809).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3414-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017-2023 Canonical, Inc. / NASL script (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
var release = chomp(release);
if (! preg(pattern:"^(14\.04|16\.04|17\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 17.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"qemu-system", pkgver:"2.0.0+dfsg-2ubuntu1.35")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-aarch64", pkgver:"2.0.0+dfsg-2ubuntu1.35")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-arm", pkgver:"2.0.0+dfsg-2ubuntu1.35")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-mips", pkgver:"2.0.0+dfsg-2ubuntu1.35")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-misc", pkgver:"2.0.0+dfsg-2ubuntu1.35")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-ppc", pkgver:"2.0.0+dfsg-2ubuntu1.35")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-sparc", pkgver:"2.0.0+dfsg-2ubuntu1.35")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-x86", pkgver:"2.0.0+dfsg-2ubuntu1.35")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system", pkgver:"1:2.5+dfsg-5ubuntu10.15")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-aarch64", pkgver:"1:2.5+dfsg-5ubuntu10.15")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-arm", pkgver:"1:2.5+dfsg-5ubuntu10.15")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-mips", pkgver:"1:2.5+dfsg-5ubuntu10.15")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-misc", pkgver:"1:2.5+dfsg-5ubuntu10.15")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-ppc", pkgver:"1:2.5+dfsg-5ubuntu10.15")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-s390x", pkgver:"1:2.5+dfsg-5ubuntu10.15")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-sparc", pkgver:"1:2.5+dfsg-5ubuntu10.15")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-x86", pkgver:"1:2.5+dfsg-5ubuntu10.15")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system", pkgver:"1:2.8+dfsg-3ubuntu2.4")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-aarch64", pkgver:"1:2.8+dfsg-3ubuntu2.4")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-arm", pkgver:"1:2.8+dfsg-3ubuntu2.4")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-mips", pkgver:"1:2.8+dfsg-3ubuntu2.4")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-misc", pkgver:"1:2.8+dfsg-3ubuntu2.4")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-ppc", pkgver:"1:2.8+dfsg-3ubuntu2.4")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-s390x", pkgver:"1:2.8+dfsg-3ubuntu2.4")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-sparc", pkgver:"1:2.8+dfsg-3ubuntu2.4")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-x86", pkgver:"1:2.8+dfsg-3ubuntu2.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-system / qemu-system-aarch64 / qemu-system-arm / etc");
}
