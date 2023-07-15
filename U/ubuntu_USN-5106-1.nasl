#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5106-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153908);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-26541",
    "CVE-2021-3612",
    "CVE-2021-22543",
    "CVE-2021-38160",
    "CVE-2021-38199",
    "CVE-2021-41073"
  );
  script_xref(name:"USN", value:"5106-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (OEM) vulnerabilities (USN-5106-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5106-1 advisory.

  - The Linux kernel through 5.8.13 does not properly enforce the Secure Boot Forbidden Signature Database
    (aka dbx) protection mechanism. This affects certs/blacklist.c and certs/system_keyring.c.
    (CVE-2020-26541)

  - An out-of-bounds memory write flaw was found in the Linux kernel's joystick devices subsystem in versions
    before 5.9-rc1, in the way the user calls ioctl JSIOCSBTNMAP. This flaw allows a local user to crash the
    system or possibly escalate their privileges on the system. The highest threat from this vulnerability is
    to confidentiality, integrity, as well as system availability. (CVE-2021-3612)

  - An issue was discovered in Linux: KVM through Improper handling of VM_IO|VM_PFNMAP vmas in KVM can bypass
    RO checks and can lead to pages being freed while still accessible by the VMM and guest. This allows users
    with the ability to start and control a VM to read/write random pages of memory and can result in local
    privilege escalation. (CVE-2021-22543)

  - ** DISPUTED ** In drivers/char/virtio_console.c in the Linux kernel before 5.13.4, data corruption or loss
    can be triggered by an untrusted device that supplies a buf->len value exceeding the buffer size. NOTE:
    the vendor indicates that the cited data corruption is not a vulnerability in any existing use case; the
    length validation was added solely for robustness in the face of anomalous host OS behavior.
    (CVE-2021-38160)

  - fs/nfs/nfs4client.c in the Linux kernel before 5.13.4 has incorrect connection-setup ordering, which
    allows operators of remote NFSv4 servers to cause a denial of service (hanging of mounts) by arranging for
    those servers to be unreachable during trunking detection. (CVE-2021-38199)

  - loop_rw_iter in fs/io_uring.c in the Linux kernel 5.10 through 5.14.6 allows local users to gain
    privileges by using IORING_OP_PROVIDE_BUFFERS to trigger a free of a kernel buffer, as demonstrated by
    using /proc//maps for exploitation. (CVE-2021-41073)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5106-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41073");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.10.0-1049-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.10.0-1049-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.10.0-1049-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.10.0-1049-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.10.0-1049-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.10-headers-5.10.0-1049");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.10-tools-5.10.0-1049");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.10-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.10.0-1049-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-20.04b");
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
  var cve_list = make_list('CVE-2020-26541', 'CVE-2021-3612', 'CVE-2021-22543', 'CVE-2021-38160', 'CVE-2021-38199', 'CVE-2021-41073');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5106-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.10.0-1049-oem', 'pkgver': '5.10.0-1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.10.0-1049-oem', 'pkgver': '5.10.0-1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem-20.04', 'pkgver': '5.10.0.1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem-20.04-edge', 'pkgver': '5.10.0.1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem-20.04b', 'pkgver': '5.10.0.1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.10.0-1049-oem', 'pkgver': '5.10.0-1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.10.0.1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04-edge', 'pkgver': '5.10.0.1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04b', 'pkgver': '5.10.0.1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.10.0-1049-oem', 'pkgver': '5.10.0-1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.10.0-1049-oem', 'pkgver': '5.10.0-1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-oem-20.04', 'pkgver': '5.10.0.1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-oem-20.04-edge', 'pkgver': '5.10.0.1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-oem-20.04b', 'pkgver': '5.10.0.1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.10-headers-5.10.0-1049', 'pkgver': '5.10.0-1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.10-tools-5.10.0-1049', 'pkgver': '5.10.0-1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.10-tools-host', 'pkgver': '5.10.0-1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.10.0-1049-oem', 'pkgver': '5.10.0-1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem-20.04', 'pkgver': '5.10.0.1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem-20.04-edge', 'pkgver': '5.10.0.1049.51'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem-20.04b', 'pkgver': '5.10.0.1049.51'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-buildinfo-5.10.0-1049-oem / linux-headers-5.10.0-1049-oem / etc');
}
