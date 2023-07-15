#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5120-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154338);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2019-19449",
    "CVE-2020-26541",
    "CVE-2020-36311",
    "CVE-2021-3612",
    "CVE-2021-3759",
    "CVE-2021-22543",
    "CVE-2021-38199",
    "CVE-2021-38207",
    "CVE-2021-40490"
  );
  script_xref(name:"USN", value:"5120-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (Azure) vulnerabilities (USN-5120-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5120-1 advisory.

  - In the Linux kernel 5.0.21, mounting a crafted f2fs filesystem image can lead to slab-out-of-bounds read
    access in f2fs_build_segment_manager in fs/f2fs/segment.c, related to init_min_max_mtime in
    fs/f2fs/segment.c (because the second argument to get_seg_entry is not validated). (CVE-2019-19449)

  - The Linux kernel through 5.8.13 does not properly enforce the Secure Boot Forbidden Signature Database
    (aka dbx) protection mechanism. This affects certs/blacklist.c and certs/system_keyring.c.
    (CVE-2020-26541)

  - An issue was discovered in the Linux kernel before 5.9. arch/x86/kvm/svm/sev.c allows attackers to cause a
    denial of service (soft lockup) by triggering destruction of a large SEV VM (which requires unregistering
    many encrypted regions), aka CID-7be74942f184. (CVE-2020-36311)

  - An out-of-bounds memory write flaw was found in the Linux kernel's joystick devices subsystem in versions
    before 5.9-rc1, in the way the user calls ioctl JSIOCSBTNMAP. This flaw allows a local user to crash the
    system or possibly escalate their privileges on the system. The highest threat from this vulnerability is
    to confidentiality, integrity, as well as system availability. (CVE-2021-3612)

  - An issue was discovered in Linux: KVM through Improper handling of VM_IO|VM_PFNMAP vmas in KVM can bypass
    RO checks and can lead to pages being freed while still accessible by the VMM and guest. This allows users
    with the ability to start and control a VM to read/write random pages of memory and can result in local
    privilege escalation. (CVE-2021-22543)

  - fs/nfs/nfs4client.c in the Linux kernel before 5.13.4 has incorrect connection-setup ordering, which
    allows operators of remote NFSv4 servers to cause a denial of service (hanging of mounts) by arranging for
    those servers to be unreachable during trunking detection. (CVE-2021-38199)

  - drivers/net/ethernet/xilinx/ll_temac_main.c in the Linux kernel before 5.12.13 allows remote attackers to
    cause a denial of service (buffer overflow and lockup) by sending heavy network traffic for about ten
    minutes. (CVE-2021-38207)

  - A race condition was discovered in ext4_write_inline_data_end in fs/ext4/inline.c in the ext4 subsystem in
    the Linux kernel through 5.13.13. (CVE-2021-40490)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5120-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3612");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.8-cloud-tools-5.8.0-1043");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.8-headers-5.8.0-1043");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.8-tools-5.8.0-1043");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.8.0-1043-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.8.0-1043-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.8.0-1043-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1043-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.8.0-1043-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.8.0-1043-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.8.0-1043-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.8.0-1043-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2019-19449', 'CVE-2020-26541', 'CVE-2020-36311', 'CVE-2021-3612', 'CVE-2021-3759', 'CVE-2021-22543', 'CVE-2021-38199', 'CVE-2021-38207', 'CVE-2021-40490');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5120-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '20.04', 'pkgname': 'linux-azure', 'pkgver': '5.8.0.1043.46~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-azure-5.8-cloud-tools-5.8.0-1043', 'pkgver': '5.8.0-1043.46~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-azure-5.8-headers-5.8.0-1043', 'pkgver': '5.8.0-1043.46~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-azure-5.8-tools-5.8.0-1043', 'pkgver': '5.8.0-1043.46~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.8.0-1043-azure', 'pkgver': '5.8.0-1043.46~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.8.0-1043-azure', 'pkgver': '5.8.0-1043.46~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '5.8.0.1043.46~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.8.0-1043-azure', 'pkgver': '5.8.0-1043.46~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-azure', 'pkgver': '5.8.0.1043.46~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.8.0-1043-azure', 'pkgver': '5.8.0-1043.46~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.8.0.1043.46~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.8.0-1043-azure', 'pkgver': '5.8.0-1043.46~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.8.0-1043-azure', 'pkgver': '5.8.0-1043.46~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.8.0-1043-azure', 'pkgver': '5.8.0-1043.46~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '5.8.0.1043.46~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.8.0-1043-azure', 'pkgver': '5.8.0-1043.46~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-azure', 'pkgver': '5.8.0.1043.46~20.04.15'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-azure / linux-azure-5.8-cloud-tools-5.8.0-1043 / etc');
}
