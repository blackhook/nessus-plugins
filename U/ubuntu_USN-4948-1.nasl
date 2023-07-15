#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4948-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149407);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-25672",
    "CVE-2021-3483",
    "CVE-2021-3489",
    "CVE-2021-3490",
    "CVE-2021-3491",
    "CVE-2021-28688",
    "CVE-2021-28951",
    "CVE-2021-28952",
    "CVE-2021-28964",
    "CVE-2021-28971",
    "CVE-2021-28972",
    "CVE-2021-29264",
    "CVE-2021-29266",
    "CVE-2021-29646",
    "CVE-2021-29647",
    "CVE-2021-29649",
    "CVE-2021-29650",
    "CVE-2021-29657",
    "CVE-2021-31916"
  );
  script_xref(name:"USN", value:"4948-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (OEM) vulnerabilities (USN-4948-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4948-1 advisory.

  - The fix for XSA-365 includes initialization of pointers such that subsequent cleanup code wouldn't use
    uninitialized or stale values. This initialization went too far and may under certain conditions also
    overwrite pointers which are in need of cleaning up. The lack of cleanup would result in leaking
    persistent grants. The leak in turn would prevent fully cleaning up after a respective guest has died,
    leaving around zombie domains. All Linux versions having the fix for XSA-365 applied are vulnerable.
    XSA-365 was classified to affect versions back to at least 3.11. (CVE-2021-28688)

  - An issue was discovered in fs/io_uring.c in the Linux kernel through 5.11.8. It allows attackers to cause
    a denial of service (deadlock) because exit may be waiting to park a SQPOLL thread, but concurrently that
    SQPOLL thread is waiting for a signal to start, aka CID-3ebba796fa25. (CVE-2021-28951)

  - An issue was discovered in the Linux kernel through 5.11.8. The sound/soc/qcom/sdm845.c soundwire device
    driver has a buffer overflow when an unexpected port ID number is encountered, aka CID-1c668e1c0a0f. (This
    has been fixed in 5.12-rc4.) (CVE-2021-28952)

  - A race condition was discovered in get_old_root in fs/btrfs/ctree.c in the Linux kernel through 5.11.8. It
    allows attackers to cause a denial of service (BUG) because of a lack of locking on an extent buffer
    before a cloning operation, aka CID-dbcc7d57bffc. (CVE-2021-28964)

  - In intel_pmu_drain_pebs_nhm in arch/x86/events/intel/ds.c in the Linux kernel through 5.11.8 on some
    Haswell CPUs, userspace applications (such as perf-fuzzer) can cause a system crash because the PEBS
    status in a PEBS record is mishandled, aka CID-d88d05a9e0b6. (CVE-2021-28971)

  - In drivers/pci/hotplug/rpadlpar_sysfs.c in the Linux kernel through 5.11.8, the RPA PCI Hotplug driver has
    a user-tolerable buffer overflow when writing a new device name to the driver from userspace, allowing
    userspace to write data to the kernel stack frame directly. This occurs because add_slot_store and
    remove_slot_store mishandle drc_name '\0' termination, aka CID-cc7a0bb058b8. (CVE-2021-28972)

  - An issue was discovered in the Linux kernel through 5.11.10. drivers/net/ethernet/freescale/gianfar.c in
    the Freescale Gianfar Ethernet driver allows attackers to cause a system crash because a negative fragment
    size is calculated in situations involving an rx queue overrun when jumbo packets are used and NAPI is
    enabled, aka CID-d8861bab48b6. (CVE-2021-29264)

  - An issue was discovered in the Linux kernel before 5.11.9. drivers/vhost/vdpa.c has a use-after-free
    because v->config_ctx has an invalid value upon re-opening a character device, aka CID-f6bbf0010ba0.
    (CVE-2021-29266)

  - An issue was discovered in the Linux kernel before 5.11.11. tipc_nl_retrieve_key in net/tipc/node.c does
    not properly validate certain data sizes, aka CID-0217ed2848e8. (CVE-2021-29646)

  - An issue was discovered in the Linux kernel before 5.11.11. qrtr_recvmsg in net/qrtr/qrtr.c allows
    attackers to obtain sensitive information from kernel memory because of a partially uninitialized data
    structure, aka CID-50535249f624. (CVE-2021-29647)

  - An issue was discovered in the Linux kernel before 5.11.11. The user mode driver (UMD) has a
    copy_process() memory leak, related to a lack of cleanup steps in kernel/usermode_driver.c and
    kernel/bpf/preload/bpf_preload_kern.c, aka CID-f60a85cad677. (CVE-2021-29649)

  - An issue was discovered in the Linux kernel before 5.11.11. The netfilter subsystem allows attackers to
    cause a denial of service (panic) because net/netfilter/x_tables.c and include/linux/netfilter/x_tables.h
    lack a full memory barrier upon the assignment of a new table value, aka CID-175e476b8cdf.
    (CVE-2021-29650)

  - An out-of-bounds (OOB) memory write flaw was found in list_devices in drivers/md/dm-ioctl.c in the Multi-
    device driver module in the Linux kernel before 5.12. A bound check failure allows an attacker with
    special user (CAP_SYS_ADMIN) privilege to gain access to out-of-bounds memory leading to a system crash or
    a leak of internal kernel information. The highest threat from this vulnerability is to system
    availability. (CVE-2021-31916)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4948-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected linux-image-5.10.0-1026-oem, linux-image-oem-20.04-edge and / or linux-image-oem-20.04b packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3491");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux eBPF ALU32 32-bit Invalid Bounds Tracking LPE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.10.0-1026-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04b");
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
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2020-25670', 'CVE-2020-25671', 'CVE-2020-25672', 'CVE-2021-3483', 'CVE-2021-3489', 'CVE-2021-3490', 'CVE-2021-3491', 'CVE-2021-28688', 'CVE-2021-28951', 'CVE-2021-28952', 'CVE-2021-28964', 'CVE-2021-28971', 'CVE-2021-28972', 'CVE-2021-29264', 'CVE-2021-29266', 'CVE-2021-29646', 'CVE-2021-29647', 'CVE-2021-29649', 'CVE-2021-29650', 'CVE-2021-29657', 'CVE-2021-31916');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4948-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'osver': '20.04', 'pkgname': 'linux-image-5.10.0-1026-oem', 'pkgver': '5.10.0-1026.27'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04-edge', 'pkgver': '5.10.0.1026.27'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04b', 'pkgver': '5.10.0.1026.27'}
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-image-5.10.0-1026-oem / linux-image-oem-20.04-edge / etc');
}