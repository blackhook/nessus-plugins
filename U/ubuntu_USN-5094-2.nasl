#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5094-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153802);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-3679",
    "CVE-2021-3732",
    "CVE-2021-22543",
    "CVE-2021-38204",
    "CVE-2021-38205"
  );
  script_xref(name:"USN", value:"5094-2");

  script_name(english:"Ubuntu 18.04 LTS : Linux kernel (Raspberry Pi) vulnerabilities (USN-5094-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5094-2 advisory.

  - drivers/usb/host/max3421-hcd.c in the Linux kernel before 5.13.6 allows physically proximate attackers to
    cause a denial of service (use-after-free and panic) by removing a MAX-3421 USB device in certain
    situations. (CVE-2021-38204)

  - A lack of CPU resource in the Linux kernel tracing module functionality in versions prior to 5.14-rc3 was
    found in the way user uses trace ring buffer in a specific way. Only privileged local users (with
    CAP_SYS_ADMIN capability) could use this flaw to starve the resources causing denial of service.
    (CVE-2021-3679)

  - A security issue was found in Linux kernel's OverlayFS subsystem where a local attacker who has the
    ability to mount the TmpFS filesystem with OverlayFS can abuse a logic bug in the overlayfs code which can
    inadvertently reveal files hidden in the original mount. (CVE-2021-3732)

  - An issue was discovered in Linux: KVM through Improper handling of VM_IO|VM_PFNMAP vmas in KVM can bypass
    RO checks and can lead to pages being freed while still accessible by the VMM and guest. This allows users
    with the ability to start and control a VM to read/write random pages of memory and can result in local
    privilege escalation. (CVE-2021-22543)

  - drivers/net/ethernet/xilinx/xilinx_emaclite.c in the Linux kernel before 5.13.3 makes it easier for
    attackers to defeat an ASLR protection mechanism because it prints a kernel pointer (i.e., the real IOMEM
    pointer). (CVE-2021-38205)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5094-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38204");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-22543");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1096-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1096-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1096-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1096-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2-headers-4.15.0-1096");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2-tools-4.15.0-1096");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1096-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi2");
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
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-3679', 'CVE-2021-3732', 'CVE-2021-22543', 'CVE-2021-38204', 'CVE-2021-38205');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5094-2');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1096-raspi2', 'pkgver': '4.15.0-1096.102'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1096-raspi2', 'pkgver': '4.15.0-1096.102'},
    {'osver': '18.04', 'pkgname': 'linux-headers-raspi2', 'pkgver': '4.15.0.1096.94'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1096-raspi2', 'pkgver': '4.15.0-1096.102'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi2', 'pkgver': '4.15.0.1096.94'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1096-raspi2', 'pkgver': '4.15.0-1096.102'},
    {'osver': '18.04', 'pkgname': 'linux-raspi2', 'pkgver': '4.15.0.1096.94'},
    {'osver': '18.04', 'pkgname': 'linux-raspi2-headers-4.15.0-1096', 'pkgver': '4.15.0-1096.102'},
    {'osver': '18.04', 'pkgname': 'linux-raspi2-tools-4.15.0-1096', 'pkgver': '4.15.0-1096.102'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1096-raspi2', 'pkgver': '4.15.0-1096.102'},
    {'osver': '18.04', 'pkgname': 'linux-tools-raspi2', 'pkgver': '4.15.0.1096.94'}
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-buildinfo-4.15.0-1096-raspi2 / linux-headers-4.15.0-1096-raspi2 / etc');
}
