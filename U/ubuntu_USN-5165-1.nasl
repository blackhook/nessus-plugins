#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5165-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155750);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-3760",
    "CVE-2021-3772",
    "CVE-2021-42327",
    "CVE-2021-42739",
    "CVE-2021-43056",
    "CVE-2021-43267",
    "CVE-2021-43389"
  );
  script_xref(name:"USN", value:"5165-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (OEM) vulnerabilities (USN-5165-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5165-1 advisory.

  - dp_link_settings_write in drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm_debugfs.c in the Linux kernel
    through 5.14.14 allows a heap-based buffer overflow by an attacker who can write a string to the AMD GPU
    display drivers debug filesystem. There are no checks on size within parse_write_buffer_into_params when
    it uses the size of copy_from_user to copy a userspace buffer into a 40-byte heap buffer. (CVE-2021-42327)

  - The firewire subsystem in the Linux kernel through 5.14.13 has a buffer overflow related to
    drivers/media/firewire/firedtv-avc.c and drivers/media/firewire/firedtv-ci.c, because avc_ca_pmt
    mishandles bounds checking. (CVE-2021-42739)

  - An issue was discovered in the Linux kernel for powerpc before 5.14.15. It allows a malicious KVM guest to
    crash the host, when the host is running on Power8, due to an arch/powerpc/kvm/book3s_hv_rmhandlers.S
    implementation bug in the handling of the SRR1 register values. (CVE-2021-43056)

  - An issue was discovered in net/tipc/crypto.c in the Linux kernel before 5.14.16. The Transparent Inter-
    Process Communication (TIPC) functionality allows remote attackers to exploit insufficient validation of
    user-supplied sizes for the MSG_CRYPTO message type. (CVE-2021-43267)

  - An issue was discovered in the Linux kernel before 5.14.15. There is an array-index-out-of-bounds flaw in
    the detach_capi_ctr function in drivers/isdn/capi/kcapi.c. (CVE-2021-43389)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5165-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43267");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.14.0-1008-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.14.0-1008-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.14.0-1008-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.14.0-1008-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.14.0-1008-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.14-headers-5.14.0-1008");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.14-tools-5.14.0-1008");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.14-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.14.0-1008-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-20.04d");
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
  var cve_list = make_list('CVE-2021-3760', 'CVE-2021-3772', 'CVE-2021-42327', 'CVE-2021-42739', 'CVE-2021-43056', 'CVE-2021-43267', 'CVE-2021-43389');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5165-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.14.0-1008-oem', 'pkgver': '5.14.0-1008.8'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.14.0-1008-oem', 'pkgver': '5.14.0-1008.8'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem-20.04d', 'pkgver': '5.14.0.1008.8'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.14.0-1008-oem', 'pkgver': '5.14.0-1008.8'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04d', 'pkgver': '5.14.0.1008.8'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.14.0-1008-oem', 'pkgver': '5.14.0-1008.8'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.14.0-1008-oem', 'pkgver': '5.14.0-1008.8'},
    {'osver': '20.04', 'pkgname': 'linux-oem-20.04d', 'pkgver': '5.14.0.1008.8'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.14-headers-5.14.0-1008', 'pkgver': '5.14.0-1008.8'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.14-tools-5.14.0-1008', 'pkgver': '5.14.0-1008.8'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.14-tools-host', 'pkgver': '5.14.0-1008.8'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.14.0-1008-oem', 'pkgver': '5.14.0-1008.8'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem-20.04d', 'pkgver': '5.14.0.1008.8'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-buildinfo-5.14.0-1008-oem / linux-headers-5.14.0-1008-oem / etc');
}
