#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3359-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101894);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2014-9900", "CVE-2016-9755", "CVE-2017-1000380", "CVE-2017-5551", "CVE-2017-5576", "CVE-2017-7346", "CVE-2017-7895", "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9150", "CVE-2017-9605");
  script_xref(name:"USN", value:"3359-1");

  script_name(english:"Ubuntu 16.10 : linux, linux-raspi2 vulnerabilities (USN-3359-1)");
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
"It was discovered that the Linux kernel did not properly initialize a
Wake- on-Lan data structure. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2014-9900)

Dmitry Vyukov, Andrey Konovalov, Florian Westphal, and Eric Dumazet
discovered that the netfiler subsystem in the Linux kernel mishandled
IPv6 packet reassembly. A local user could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2016-9755)

Alexander Potapenko discovered a race condition in the Advanced Linux
Sound Architecture (ALSA) subsystem in the Linux kernel. A local
attacker could use this to expose sensitive information (kernel
memory). (CVE-2017-1000380)

It was discovered that the Linux kernel did not clear the setgid bit
during a setxattr call on a tmpfs filesystem. A local attacker could
use this to gain elevated group privileges. (CVE-2017-5551)

Murray McAllister discovered that an integer overflow existed in the
VideoCore DRM driver of the Linux kernel. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2017-5576)

Li Qiang discovered that the DRM driver for VMware Virtual GPUs in the
Linux kernel did not properly validate some ioctl arguments. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2017-7346)

Tuomas Haanpaa and Ari Kauppi discovered that the NFSv2 and NFSv3
server implementations in the Linux kernel did not properly check for
the end of buffer. A remote attacker could use this to craft requests
that cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2017-7895)

It was discovered that an integer underflow existed in the Edgeport
USB Serial Converter device driver of the Linux kernel. An attacker
with physical access could use this to expose sensitive information
(kernel memory). (CVE-2017-8924)

It was discovered that the USB ZyXEL omni.net LCD PLUS driver in the
Linux kernel did not properly perform reference counting. A local
attacker could use this to cause a denial of service (tty exhaustion).
(CVE-2017-8925)

Jann Horn discovered that bpf in Linux kernel does not restrict the
output of the print_bpf_insn function. A local attacker could use this
to obtain sensitive address information. (CVE-2017-9150)

Murray McAllister discovered that the DRM driver for VMware Virtual
GPUs in the Linux kernel did not properly initialize memory. A local
attacker could use this to expose sensitive information (kernel
memory). (CVE-2017-9605).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3359-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.8-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.8-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.8-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.8-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017-2023 Canonical, Inc. / NASL script (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
var release = chomp(release);
if (! preg(pattern:"^(16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2014-9900", "CVE-2016-9755", "CVE-2017-1000380", "CVE-2017-5551", "CVE-2017-5576", "CVE-2017-7346", "CVE-2017-7895", "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9150", "CVE-2017-9605");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3359-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"16.10", pkgname:"linux-image-4.8.0-1043-raspi2", pkgver:"4.8.0-1043.47")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"linux-image-4.8.0-59-generic", pkgver:"4.8.0-59.64")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"linux-image-4.8.0-59-generic-lpae", pkgver:"4.8.0-59.64")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"linux-image-4.8.0-59-lowlatency", pkgver:"4.8.0-59.64")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"linux-image-generic", pkgver:"4.8.0.59.72")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"linux-image-generic-lpae", pkgver:"4.8.0.59.72")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"linux-image-lowlatency", pkgver:"4.8.0.59.72")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"linux-image-raspi2", pkgver:"4.8.0.1043.47")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.8-generic / linux-image-4.8-generic-lpae / etc");
}
