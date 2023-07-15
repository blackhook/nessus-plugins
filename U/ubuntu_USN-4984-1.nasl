#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4984-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150292);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2021-3483",
    "CVE-2021-28038",
    "CVE-2021-28660",
    "CVE-2021-28688",
    "CVE-2021-28950",
    "CVE-2021-28952",
    "CVE-2021-28964",
    "CVE-2021-28971",
    "CVE-2021-28972",
    "CVE-2021-29647",
    "CVE-2021-30002",
    "CVE-2021-31916",
    "CVE-2021-33033"
  );
  script_xref(name:"USN", value:"4984-1");

  script_name(english:"Ubuntu 20.04 LTS / 20.10 : Linux kernel vulnerabilities (USN-4984-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 20.10 host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4984-1 advisory.

  - A flaw was found in the Nosy driver in the Linux kernel. This issue allows a device to be inserted twice
    into a doubly-linked list, leading to a use-after-free when one of these devices is removed. The highest
    threat from this vulnerability is to confidentiality, integrity, as well as system availability. Versions
    before kernel 5.12-rc6 are affected (CVE-2021-3483)

  - An issue was discovered in the Linux kernel through 5.11.3, as used with Xen PV. A certain part of the
    netback driver lacks necessary treatment of errors such as failed memory allocations (as a result of
    changes to the handling of grant mapping errors). A host OS denial of service may occur during misbehavior
    of a networking frontend driver. NOTE: this issue exists because of an incomplete fix for CVE-2021-26931.
    (CVE-2021-28038)

  - rtw_wx_set_scan in drivers/staging/rtl8188eu/os_dep/ioctl_linux.c in the Linux kernel through 5.11.6
    allows writing beyond the end of the ->ssid[] array. NOTE: from the perspective of kernel.org releases,
    CVE IDs are not normally used for drivers/staging/* (unfinished work); however, system integrators may
    have situations in which a drivers/staging issue is relevant to their own customer base. (CVE-2021-28660)

  - The fix for XSA-365 includes initialization of pointers such that subsequent cleanup code wouldn't use
    uninitialized or stale values. This initialization went too far and may under certain conditions also
    overwrite pointers which are in need of cleaning up. The lack of cleanup would result in leaking
    persistent grants. The leak in turn would prevent fully cleaning up after a respective guest has died,
    leaving around zombie domains. All Linux versions having the fix for XSA-365 applied are vulnerable.
    XSA-365 was classified to affect versions back to at least 3.11. (CVE-2021-28688)

  - An issue was discovered in fs/fuse/fuse_i.h in the Linux kernel before 5.11.8. A stall on CPU can occur
    because a retry loop continually finds the same bad inode, aka CID-775c5033a0d1. (CVE-2021-28950)

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

  - An issue was discovered in the Linux kernel before 5.11.11. qrtr_recvmsg in net/qrtr/qrtr.c allows
    attackers to obtain sensitive information from kernel memory because of a partially uninitialized data
    structure, aka CID-50535249f624. (CVE-2021-29647)

  - An issue was discovered in the Linux kernel before 5.11.3 when a webcam device exists. video_usercopy in
    drivers/media/v4l2-core/v4l2-ioctl.c has a memory leak for large arguments, aka CID-fb18802a338b.
    (CVE-2021-30002)

  - An out-of-bounds (OOB) memory write flaw was found in list_devices in drivers/md/dm-ioctl.c in the Multi-
    device driver module in the Linux kernel before 5.12. A bound check failure allows an attacker with
    special user (CAP_SYS_ADMIN) privilege to gain access to out-of-bounds memory leading to a system crash or
    a leak of internal kernel information. The highest threat from this vulnerability is to system
    availability. (CVE-2021-31916)

  - The Linux kernel before 5.11.14 has a use-after-free in cipso_v4_genopt in net/ipv4/cipso_ipv4.c because
    the CIPSO and CALIPSO refcounting for the DOI definitions is mishandled, aka CID-ad5d07f4a9cd. This leads
    to writing an arbitrary value. (CVE-2021-33033)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4984-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1028-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1031-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1032-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1033-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1035-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-55-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-55-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-55-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-55-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04-edge");
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
if (! preg(pattern:"^(20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2021-3483', 'CVE-2021-28038', 'CVE-2021-28660', 'CVE-2021-28688', 'CVE-2021-28950', 'CVE-2021-28952', 'CVE-2021-28964', 'CVE-2021-28971', 'CVE-2021-28972', 'CVE-2021-29647', 'CVE-2021-30002', 'CVE-2021-31916', 'CVE-2021-33033');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4984-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'osver': '20.04', 'pkgname': 'linux-image-5.8.0-55-generic', 'pkgver': '5.8.0-55.62~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.8.0-55-generic-64k', 'pkgver': '5.8.0-55.62~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.8.0-55-generic-lpae', 'pkgver': '5.8.0-55.62~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.8.0-55-lowlatency', 'pkgver': '5.8.0-55.62~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.8.0.55.62~20.04.39'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.8.0.55.62~20.04.39'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.8.0.55.62~20.04.39'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.8.0.55.62~20.04.39'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.8.0.55.62~20.04.39'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.8.0.55.62~20.04.39'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.8.0.55.62~20.04.39'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.8.0.55.62~20.04.39'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.8.0.55.62~20.04.39'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.8.0.55.62~20.04.39'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1028-kvm', 'pkgver': '5.8.0-1028.30'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1031-oracle', 'pkgver': '5.8.0-1031.32'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1032-gcp', 'pkgver': '5.8.0-1032.34'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1033-azure', 'pkgver': '5.8.0-1033.35'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1035-aws', 'pkgver': '5.8.0-1035.37'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-55-generic', 'pkgver': '5.8.0-55.62'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-55-generic-64k', 'pkgver': '5.8.0-55.62'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-55-generic-lpae', 'pkgver': '5.8.0-55.62'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-55-lowlatency', 'pkgver': '5.8.0-55.62'},
    {'osver': '20.10', 'pkgname': 'linux-image-aws', 'pkgver': '5.8.0.1035.37'},
    {'osver': '20.10', 'pkgname': 'linux-image-azure', 'pkgver': '5.8.0.1033.33'},
    {'osver': '20.10', 'pkgname': 'linux-image-gcp', 'pkgver': '5.8.0.1032.32'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic', 'pkgver': '5.8.0.55.60'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-64k', 'pkgver': '5.8.0.55.60'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.8.0.55.60'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.8.0.55.60'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.8.0.55.60'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.8.0.55.60'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.8.0.55.60'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.8.0.55.60'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.8.0.55.60'},
    {'osver': '20.10', 'pkgname': 'linux-image-gke', 'pkgver': '5.8.0.1032.32'},
    {'osver': '20.10', 'pkgname': 'linux-image-kvm', 'pkgver': '5.8.0.1028.30'},
    {'osver': '20.10', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.8.0.55.60'},
    {'osver': '20.10', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.8.0.55.60'},
    {'osver': '20.10', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.8.0.55.60'},
    {'osver': '20.10', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.8.0.55.60'},
    {'osver': '20.10', 'pkgname': 'linux-image-oracle', 'pkgver': '5.8.0.1031.30'},
    {'osver': '20.10', 'pkgname': 'linux-image-virtual', 'pkgver': '5.8.0.55.60'},
    {'osver': '20.10', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.8.0.55.60'},
    {'osver': '20.10', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.8.0.55.60'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-image-5.8.0-1028-kvm / linux-image-5.8.0-1031-oracle / etc');
}