#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5010-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151680);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-15469",
    "CVE-2020-29443",
    "CVE-2020-35504",
    "CVE-2020-35505",
    "CVE-2020-35517",
    "CVE-2021-3392",
    "CVE-2021-3409",
    "CVE-2021-3416",
    "CVE-2021-3527",
    "CVE-2021-3544",
    "CVE-2021-3545",
    "CVE-2021-3546",
    "CVE-2021-3582",
    "CVE-2021-3592",
    "CVE-2021-3593",
    "CVE-2021-3594",
    "CVE-2021-3595",
    "CVE-2021-3607",
    "CVE-2021-3608",
    "CVE-2021-20221",
    "CVE-2021-20257"
  );
  script_xref(name:"USN", value:"5010-1");
  script_xref(name:"IAVB", value:"2020-B-0041-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 : QEMU vulnerabilities (USN-5010-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5010-1 advisory.

  - In QEMU 4.2.0, a MemoryRegionOps object may lack read/write callback methods, leading to a NULL pointer
    dereference. (CVE-2020-15469)

  - ide_atapi_cmd_reply_end in hw/ide/atapi.c in QEMU 5.1.0 allows out-of-bounds read access because a buffer
    index is not validated. (CVE-2020-29443)

  - A NULL pointer dereference flaw was found in the SCSI emulation support of QEMU in versions before 6.0.0.
    This flaw allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of
    service. The highest threat from this vulnerability is to system availability. (CVE-2020-35504)

  - A NULL pointer dereference flaw was found in the am53c974 SCSI host bus adapter emulation of QEMU in
    versions before 6.0.0. This issue occurs while handling the 'Information Transfer' command. This flaw
    allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of service.
    The highest threat from this vulnerability is to system availability. (CVE-2020-35505)

  - A flaw was found in qemu. A host privilege escalation issue was found in the virtio-fs shared file system
    daemon where a privileged guest user is able to create a device special file in the shared directory and
    use it to r/w access host devices. (CVE-2020-35517)

  - A use-after-free flaw was found in the MegaRAID emulator of QEMU. This issue occurs while processing SCSI
    I/O requests in the case of an error mptsas_free_request() that does not dequeue the request object 'req'
    from a pending requests queue. This flaw allows a privileged guest user to crash the QEMU process on the
    host, resulting in a denial of service. Versions between 2.10.0 and 5.2.0 are potentially affected.
    (CVE-2021-3392)

  - The patch for CVE-2020-17380/CVE-2020-25085 was found to be ineffective, thus making QEMU vulnerable to
    the out-of-bounds read/write access issues previously found in the SDHCI controller emulation code. This
    flaw allows a malicious privileged guest to crash the QEMU process on the host, resulting in a denial of
    service or potential code execution. QEMU up to (including) 5.2.0 is affected by this. (CVE-2021-3409)

  - A potential stack overflow via infinite loop issue was found in various NIC emulators of QEMU in versions
    up to and including 5.2.0. The issue occurs in loopback mode of a NIC wherein reentrant DMA checks get
    bypassed. A guest user/process may use this flaw to consume CPU cycles or crash the QEMU process on the
    host resulting in DoS scenario. (CVE-2021-3416)

  - A flaw was found in the USB redirector device (usb-redir) of QEMU. Small USB packets are combined into a
    single, large transfer request, to reduce the overhead and improve performance. The combined size of the
    bulk transfer is used to dynamically allocate a variable length array (VLA) on the stack without proper
    validation. Since the total size is not bounded, a malicious guest could use this flaw to influence the
    array length and cause the QEMU process to perform an excessive allocation on the stack, resulting in a
    denial of service. (CVE-2021-3527)

  - Several memory leaks were found in the virtio vhost-user GPU device (vhost-user-gpu) of QEMU in versions
    up to and including 6.0. They exist in contrib/vhost-user-gpu/vhost-user-gpu.c and contrib/vhost-user-
    gpu/virgl.c due to improper release of memory (i.e., free) after effective lifetime. (CVE-2021-3544)

  - An information disclosure vulnerability was found in the virtio vhost-user GPU device (vhost-user-gpu) of
    QEMU in versions up to and including 6.0. The flaw exists in virgl_cmd_get_capset_info() in contrib/vhost-
    user-gpu/virgl.c and could occur due to the read of uninitialized memory. A malicious guest could exploit
    this issue to leak memory from the host. (CVE-2021-3545)

  - A flaw was found in vhost-user-gpu of QEMU in versions up to and including 6.0. An out-of-bounds write
    vulnerability can allow a malicious guest to crash the QEMU process on the host resulting in a denial of
    service or potentially execute arbitrary code on the host with the privileges of the QEMU process. The
    highest threat from this vulnerability is to data confidentiality and integrity as well as system
    availability. (CVE-2021-3546)

  - An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw
    exists in the bootp_input() function and could occur while processing a udp packet that is smaller than
    the size of the 'bootp_t' structure. A malicious guest could use this flaw to leak 10 bytes of
    uninitialized heap memory from the host. The highest threat from this vulnerability is to data
    confidentiality. This flaw affects libslirp versions prior to 4.6.0. (CVE-2021-3592)

  - An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw
    exists in the udp6_input() function and could occur while processing a udp packet that is smaller than the
    size of the 'udphdr' structure. This issue may lead to out-of-bounds read access or indirect host memory
    disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw
    affects libslirp versions prior to 4.6.0. (CVE-2021-3593)

  - An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw
    exists in the udp_input() function and could occur while processing a udp packet that is smaller than the
    size of the 'udphdr' structure. This issue may lead to out-of-bounds read access or indirect host memory
    disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw
    affects libslirp versions prior to 4.6.0. (CVE-2021-3594)

  - An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw
    exists in the tftp_input() function and could occur while processing a udp packet that is smaller than the
    size of the 'tftp_t' structure. This issue may lead to out-of-bounds read access or indirect host memory
    disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw
    affects libslirp versions prior to 4.6.0. (CVE-2021-3595)

  - An out-of-bounds heap buffer access issue was found in the ARM Generic Interrupt Controller emulator of
    QEMU up to and including qemu 4.2.0on aarch64 platform. The issue occurs because while writing an
    interrupt ID to the controller memory area, it is not masked to be 4 bits wide. It may lead to the said
    issue while updating controller state fields and their subsequent processing. A privileged guest user may
    use this flaw to crash the QEMU process on the host resulting in DoS scenario. (CVE-2021-20221)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5010-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3546");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
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

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|20\.10|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 20.10 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'qemu', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '18.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '18.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '18.04', 'pkgname': 'qemu-kvm', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '18.04', 'pkgname': 'qemu-system', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '18.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '18.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '18.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '18.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '18.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '18.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '18.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '18.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '18.04', 'pkgname': 'qemu-user', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '18.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '18.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '18.04', 'pkgname': 'qemu-utils', 'pkgver': '1:2.11+dfsg-1ubuntu7.37'},
    {'osver': '20.04', 'pkgname': 'qemu', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-kvm', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-system', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-system-data', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-system-gui', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-system-x86-microvm', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-system-x86-xen', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-user', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.04', 'pkgname': 'qemu-utils', 'pkgver': '1:4.2-3ubuntu6.17'},
    {'osver': '20.10', 'pkgname': 'qemu', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-block-extra', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-kvm', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-system', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-system-arm', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-system-common', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-system-data', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-system-gui', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-system-mips', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-system-misc', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-system-x86', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-system-x86-microvm', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-system-x86-xen', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-user', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-user-static', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '20.10', 'pkgname': 'qemu-utils', 'pkgver': '1:5.0-5ubuntu9.9'},
    {'osver': '21.04', 'pkgname': 'qemu', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-system', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-system-data', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-system-gui', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-system-x86-microvm', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-system-x86-xen', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-user', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'qemu-utils', 'pkgver': '1:5.2+dfsg-9ubuntu3.1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-block-extra / qemu-guest-agent / qemu-kvm / qemu-system / etc');
}
