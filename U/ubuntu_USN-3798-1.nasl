#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3798-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118329);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2015-8539", "CVE-2016-7913", "CVE-2017-0794", "CVE-2017-15299", "CVE-2017-18216", "CVE-2018-1000004", "CVE-2018-7566", "CVE-2018-9518");
  script_xref(name:"USN", value:"3798-1");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel vulnerabilities (USN-3798-1)");
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
"Dmitry Vyukov discovered that the key management subsystem in the
Linux kernel did not properly restrict adding a key that already
exists but is negatively instantiated. A local attacker could use this
to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2015-8539)

It was discovered that a use-after-free vulnerability existed in the
device driver for XCeive xc2028/xc3028 tuners in the Linux kernel. A
local attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2016-7913)

Pengfei Ding (Ding Peng Fei ), Chenfu Bao (Bao Chen Fu ), and Lenx Wei
(Wei Tao ) discovered a race condition in the generic SCSI driver (sg)
of the Linux kernel. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2017-0794)

Eric Biggers discovered that the key management subsystem in the Linux
kernel did not properly restrict adding a key that already exists but
is uninstantiated. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2017-15299)

It was discovered that a NULL pointer dereference could be triggered
in the OCFS2 file system implementation in the Linux kernel. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2017-18216)

Luo Quan and Wei Yang discovered that a race condition existed in the
Advanced Linux Sound Architecture (ALSA) subsystem of the Linux kernel
when handling ioctl()s. A local attacker could use this to cause a
denial of service (system deadlock). (CVE-2018-1000004)

Fan Long Fei  discovered that a race condition existed in the Advanced
Linux Sound Architecture (ALSA) subsystem of the Linux kernel that
could lead to a use- after-free or an out-of-bounds buffer access. A
local attacker with access to /dev/snd/seq could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2018-7566)

It was discovered that a buffer overflow existed in the NFC Logical
Link Control Protocol (llcp) implementation in the Linux kernel. An
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2018-9518).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3798-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7913");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/23");
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
if (! preg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2015-8539", "CVE-2016-7913", "CVE-2017-0794", "CVE-2017-15299", "CVE-2017-18216", "CVE-2018-1000004", "CVE-2018-7566", "CVE-2018-9518");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3798-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-161-generic", pkgver:"3.13.0-161.211")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-161-generic-lpae", pkgver:"3.13.0-161.211")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-161-lowlatency", pkgver:"3.13.0-161.211")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic", pkgver:"3.13.0.161.171")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic-lpae", pkgver:"3.13.0.161.171")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-highbank", pkgver:"3.13.0.161.171")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-lowlatency", pkgver:"3.13.0.161.171")) flag++;

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
