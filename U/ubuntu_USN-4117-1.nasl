#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4117-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128477);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-10126", "CVE-2019-10638", "CVE-2019-12984", "CVE-2019-13233", "CVE-2019-13272", "CVE-2019-14283", "CVE-2019-14284", "CVE-2019-3846", "CVE-2019-3900");
  script_xref(name:"USN", value:"4117-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/10");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Ubuntu 19.04 : linux-aws vulnerabilities (USN-4117-1)");
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
"It was discovered that a heap buffer overflow existed in the Marvell
Wireless LAN device driver for the Linux kernel. An attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2019-10126)

Amit Klein and Benny Pinkas discovered that the Linux kernel did not
sufficiently randomize IP ID values generated for connectionless
networking protocols. A remote attacker could use this to track
particular Linux devices. (CVE-2019-10638)

It was discovered that a NULL pointer dereference vulnerability
existed in the Near-field communication (NFC) implementation in the
Linux kernel. A local attacker could use this to cause a denial of
service (system crash). (CVE-2019-12984)

Jann Horn discovered a use-after-free vulnerability in the Linux
kernel when accessing LDT entries in some situations. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2019-13233)

Jann Horn discovered that the ptrace implementation in the Linux
kernel did not properly record credentials in some situations. A local
attacker could use this to cause a denial of service (system crash) or
possibly gain administrative privileges. (CVE-2019-13272)

It was discovered that the floppy driver in the Linux kernel did not
properly validate meta data, leading to a buffer overread. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2019-14283)

It was discovered that the floppy driver in the Linux kernel did not
properly validate ioctl() calls, leading to a division-by-zero. A
local attacker could use this to cause a denial of service (system
crash). (CVE-2019-14284)

It was discovered that the Marvell Wireless LAN device driver in the
Linux kernel did not properly validate the BSS descriptor. A local
attacker could possibly use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2019-3846)

Jason Wang discovered that an infinite loop vulnerability existed in
the virtio net driver in the Linux kernel. A local attacker in a guest
VM could possibly use this to cause a denial of service in the host
system. (CVE-2019-3900).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4117-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected linux-image-5.0-aws and / or linux-image-aws
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3846");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Polkit pkexec helper PTRACE_TRACEME local root exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2019-2023 Canonical, Inc. / NASL script (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(19\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 19.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-10126", "CVE-2019-10638", "CVE-2019-12984", "CVE-2019-13233", "CVE-2019-13272", "CVE-2019-14283", "CVE-2019-14284", "CVE-2019-3846", "CVE-2019-3900");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4117-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1014-aws", pkgver:"5.0.0-1014.16")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-aws", pkgver:"5.0.0.1014.15")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-5.0-aws / linux-image-aws");
}
