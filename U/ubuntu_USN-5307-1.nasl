#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5307-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158457);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2021-3544",
    "CVE-2021-3545",
    "CVE-2021-3546",
    "CVE-2021-3682",
    "CVE-2021-3713",
    "CVE-2021-3748",
    "CVE-2021-3930",
    "CVE-2021-4158",
    "CVE-2021-20196",
    "CVE-2021-20203",
    "CVE-2022-0358"
  );
  script_xref(name:"USN", value:"5307-1");
  script_xref(name:"IAVB", value:"2020-B-0075-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 : QEMU vulnerabilities (USN-5307-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5307-1 advisory.

  - Several memory leaks were found in the virtio vhost-user GPU device (vhost-user-gpu) of QEMU in versions
    up to and including 6.0. They exist in contrib/vhost-user-gpu/vhost-user-gpu.c and contrib/vhost-user-
    gpu/virgl.c due to improper release of memory (i.e., free) after effective lifetime. (CVE-2021-3544)

  - An information disclosure vulnerability was found in the virtio vhost-user GPU device (vhost-user-gpu) of
    QEMU in versions up to and including 6.0. The flaw exists in virgl_cmd_get_capset_info() in contrib/vhost-
    user-gpu/virgl.c and could occur due to the read of uninitialized memory. A malicious guest could exploit
    this issue to leak memory from the host. (CVE-2021-3545)

  - An out-of-bounds write vulnerability was found in the virtio vhost-user GPU device (vhost-user-gpu) of
    QEMU in versions up to and including 6.0. The flaw occurs while processing the 'VIRTIO_GPU_CMD_GET_CAPSET'
    command from the guest. It could allow a privileged guest user to crash the QEMU process on the host,
    resulting in a denial of service condition, or potential code execution with the privileges of the QEMU
    process. (CVE-2021-3546)

  - A flaw was found in the USB redirector device emulation of QEMU in versions prior to 6.1.0-rc2. It occurs
    when dropping packets during a bulk transfer from a SPICE client due to the packet queue being full. A
    malicious SPICE client could use this flaw to make QEMU call free() with faked heap chunk metadata,
    resulting in a crash of QEMU or potential code execution with the privileges of the QEMU process on the
    host. (CVE-2021-3682)

  - An out-of-bounds write flaw was found in the UAS (USB Attached SCSI) device emulation of QEMU in versions
    prior to 6.2.0-rc0. The device uses the guest supplied stream number unchecked, which can lead to out-of-
    bounds access to the UASDevice->data3 and UASDevice->status3 fields. A malicious guest user could use this
    flaw to crash QEMU or potentially achieve code execution with the privileges of the QEMU process on the
    host. (CVE-2021-3713)

  - An off-by-one error was found in the SCSI device emulation in QEMU. It could occur while processing MODE
    SELECT commands in mode_sense_page() if the 'page' argument was set to MODE_PAGE_ALLS (0x3f). A malicious
    guest could use this flaw to potentially crash QEMU, resulting in a denial of service condition.
    (CVE-2021-3930)

  - A NULL pointer dereference flaw was found in the floppy disk emulator of QEMU. This issue occurs while
    processing read/write ioport commands if the selected floppy drive is not initialized with a block device.
    This flaw allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of
    service. The highest threat from this vulnerability is to system availability. (CVE-2021-20196)

  - An integer overflow issue was found in the vmxnet3 NIC emulator of the QEMU for versions up to v5.2.0. It
    may occur if a guest was to supply invalid values for rx/tx queue size or other NIC parameters. A
    privileged guest user may use this flaw to crash the QEMU process on the host resulting in DoS scenario.
    (CVE-2021-20203)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5307-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3748");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3682");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-block-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86-microvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-user-binfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-utils");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'qemu', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '18.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '18.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '18.04', 'pkgname': 'qemu-kvm', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '18.04', 'pkgname': 'qemu-system', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '18.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '18.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '18.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '18.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '18.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '18.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '18.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '18.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '18.04', 'pkgname': 'qemu-user', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '18.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '18.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '18.04', 'pkgname': 'qemu-utils', 'pkgver': '1:2.11+dfsg-1ubuntu7.39'},
    {'osver': '20.04', 'pkgname': 'qemu', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-kvm', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-system', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-system-data', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-system-gui', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-system-x86-microvm', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-system-x86-xen', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-user', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '20.04', 'pkgname': 'qemu-utils', 'pkgver': '1:4.2-3ubuntu6.21'},
    {'osver': '21.10', 'pkgname': 'qemu', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-block-extra', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-system', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-system-arm', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-system-common', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-system-data', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-system-gui', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-system-mips', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-system-misc', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-system-x86', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-system-x86-microvm', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-system-x86-xen', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-user', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-user-static', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'qemu-utils', 'pkgver': '1:6.0+dfsg-2expubuntu1.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-block-extra / qemu-guest-agent / qemu-kvm / qemu-system / etc');
}
