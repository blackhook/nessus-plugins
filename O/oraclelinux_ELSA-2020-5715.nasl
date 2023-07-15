#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5715.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137291);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2019-9500",
    "CVE-2019-9503",
    "CVE-2019-11599",
    "CVE-2019-12819",
    "CVE-2019-14896",
    "CVE-2019-14897",
    "CVE-2019-15505",
    "CVE-2019-18282",
    "CVE-2019-19045",
    "CVE-2019-19056",
    "CVE-2019-19057",
    "CVE-2019-19058",
    "CVE-2019-19524",
    "CVE-2019-19537",
    "CVE-2019-19767",
    "CVE-2019-20636",
    "CVE-2020-0543",
    "CVE-2020-11608",
    "CVE-2020-11609",
    "CVE-2020-11668",
    "CVE-2020-12768"
  );

  script_name(english:"Oracle Linux 7 : Unbreakable Enterprise kernel (ELSA-2020-5715)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-5715 advisory.

  - The coredump implementation in the Linux kernel before 5.0.10 does not use locking or other mechanisms to
    prevent vma layout or vma flags changes while it runs, which allows local users to obtain sensitive
    information, cause a denial of service, or possibly have unspecified other impact by triggering a race
    condition with mmget_not_zero or get_task_mm calls. This is related to fs/userfaultfd.c, mm/mmap.c,
    fs/proc/task_mmu.c, and drivers/infiniband/core/uverbs_main.c. (CVE-2019-11599)

  - The Broadcom brcmfmac WiFi driver prior to commit 1b5e2423164b3670e8bc9174e4762d297990deff is vulnerable
    to a heap buffer overflow. If the Wake-up on Wireless LAN functionality is configured, a malicious event
    frame can be constructed to trigger an heap buffer overflow in the brcmf_wowl_nd_results function. This
    vulnerability can be exploited with compromised chipsets to compromise the host, or when used in
    combination with CVE-2019-9503, can be used remotely. In the worst case scenario, by sending specially-
    crafted WiFi packets, a remote, unauthenticated attacker may be able to execute arbitrary code on a
    vulnerable system. More typically, this vulnerability will result in denial-of-service conditions.
    (CVE-2019-9500)

  - The Broadcom brcmfmac WiFi driver prior to commit a4176ec356c73a46c07c181c6d04039fafa34a9f is vulnerable
    to a frame validation bypass. If the brcmfmac driver receives a firmware event frame from a remote source,
    the is_wlc_event_frame function will cause this frame to be discarded and unprocessed. If the driver
    receives the firmware event frame from the host, the appropriate handler is called. This frame validation
    can be bypassed if the bus used is USB (for instance by a wifi dongle). This can allow firmware event
    frames from a remote source to be processed. In the worst case scenario, by sending specially-crafted WiFi
    packets, a remote, unauthenticated attacker may be able to execute arbitrary code on a vulnerable system.
    More typically, this vulnerability will result in denial-of-service conditions. (CVE-2019-9503)

  - A memory leak in the mwifiex_pcie_alloc_cmdrsp_buf() function in
    drivers/net/wireless/marvell/mwifiex/pcie.c in the Linux kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering mwifiex_map_pci_memory() failures, aka CID-
    db8fd2cde932. (CVE-2019-19056)

  - An issue was discovered in the stv06xx subsystem in the Linux kernel before 5.6.1.
    drivers/media/usb/gspca/stv06xx/stv06xx.c and drivers/media/usb/gspca/stv06xx/stv06xx_pb0100.c mishandle
    invalid descriptors, as demonstrated by a NULL pointer dereference, aka CID-485b06aadb93. (CVE-2020-11609)

  - In the Linux kernel before 5.6.1, drivers/media/usb/gspca/xirlink_cit.c (aka the Xirlink camera USB
    driver) mishandles invalid descriptors, aka CID-a246b4d54770. (CVE-2020-11668)

  - A stack-based buffer overflow was found in the Linux kernel, version kernel-2.6.32, in Marvell WiFi chip
    driver. An attacker is able to cause a denial of service (system crash) or, possibly execute arbitrary
    code, when a STA works in IBSS mode (allows connecting stations together without the use of an AP) and
    connects to another STA. (CVE-2019-14897)

  - In the Linux kernel before 5.3.12, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/input/ff-memless.c driver, aka CID-fa3a5a1880c9. (CVE-2019-19524)

  - In the Linux kernel before 5.2.10, there is a race condition bug that can be caused by a malicious USB
    device in the USB character device driver layer, aka CID-303911cfc5b9. This affects
    drivers/usb/core/file.c. (CVE-2019-19537)

  - In the Linux kernel before 5.4.12, drivers/input/input.c has out-of-bounds writes via a crafted keycode
    table, as demonstrated by input_set_keycode, aka CID-cb222aed03d7. (CVE-2019-20636)

  - An issue was discovered in the Linux kernel before 5.0. The function __mdiobus_register() in
    drivers/net/phy/mdio_bus.c calls put_device(), which will trigger a fixed_mdio_bus_init use-after-free.
    This will cause a denial of service. (CVE-2019-12819)

  - Two memory leaks in the mwifiex_pcie_init_evt_ring() function in
    drivers/net/wireless/marvell/mwifiex/pcie.c in the Linux kernel through 5.3.11 allow attackers to cause a
    denial of service (memory consumption) by triggering mwifiex_map_pci_memory() failures, aka
    CID-d10dcb615c8e. (CVE-2019-19057)

  - A heap-based buffer overflow vulnerability was found in the Linux kernel, version kernel-2.6.32, in
    Marvell WiFi chip driver. A remote attacker could cause a denial of service (system crash) or, possibly
    execute arbitrary code, when the lbs_ibss_join_existing function is called after a STA connects to an AP.
    (CVE-2019-14896)

  - drivers/media/usb/dvb-usb/technisat-usb2.c in the Linux kernel through 5.2.9 has an out-of-bounds read via
    crafted USB device traffic (which may be remote via usbip or usbredir). (CVE-2019-15505)

  - The flow_dissector feature in the Linux kernel 4.3 through 5.x before 5.3.10 has a device tracking
    vulnerability, aka CID-55667441c84f. This occurs because the auto flowlabel of a UDP IPv6 packet relies on
    a 32-bit hashrnd value as a secret, and because jhash (instead of siphash) is used. The hashrnd value
    remains the same starting from boot time, and can be inferred by an attacker. This affects
    net/core/flow_dissector.c and related code. (CVE-2019-18282)

  - The Linux kernel before 5.4.2 mishandles ext4_expand_extra_isize, as demonstrated by use-after-free errors
    in __ext4_expand_extra_isize and ext4_xattr_set_entry, related to fs/ext4/inode.c and fs/ext4/super.c, aka
    CID-4ea99936a163. (CVE-2019-19767)

  - Incomplete cleanup from specific special register read operations in some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2020-0543)

  - ** DISPUTED ** An issue was discovered in the Linux kernel before 5.6. svm_cpu_uninit in
    arch/x86/kvm/svm.c has a memory leak, aka CID-d80b64ff297e. NOTE: third parties dispute this issue because
    it's a one-time leak at the boot, the size is negligible, and it can't be triggered at will.
    (CVE-2020-12768)

  - A memory leak in the mlx5_fpga_conn_create_cq() function in
    drivers/net/ethernet/mellanox/mlx5/core/fpga/conn.c in the Linux kernel before 5.3.11 allows attackers to
    cause a denial of service (memory consumption) by triggering mlx5_vector2eqn() failures, aka
    CID-c8c2a057fdc7. (CVE-2019-19045)

  - A memory leak in the alloc_sgtable() function in drivers/net/wireless/intel/iwlwifi/fw/dbg.c in the Linux
    kernel through 5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering
    alloc_page() failures, aka CID-b4b814fec1a5. (CVE-2019-19058)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-5715.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15505");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.14.35-1902.303.4.1.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2020-5715');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.14';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-4.14.35-1902.303.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.14.35'},
    {'reference':'kernel-uek-4.14.35-1902.303.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.14.35'},
    {'reference':'kernel-uek-debug-4.14.35-1902.303.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.14.35'},
    {'reference':'kernel-uek-debug-4.14.35-1902.303.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.14.35'},
    {'reference':'kernel-uek-debug-devel-4.14.35-1902.303.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.14.35'},
    {'reference':'kernel-uek-debug-devel-4.14.35-1902.303.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.14.35'},
    {'reference':'kernel-uek-devel-4.14.35-1902.303.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.14.35'},
    {'reference':'kernel-uek-devel-4.14.35-1902.303.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.14.35'},
    {'reference':'kernel-uek-doc-4.14.35-1902.303.4.1.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.14.35'},
    {'reference':'kernel-uek-headers-4.14.35-1902.303.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-4.14.35'},
    {'reference':'kernel-uek-tools-4.14.35-1902.303.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-4.14.35'},
    {'reference':'kernel-uek-tools-4.14.35-1902.303.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-4.14.35'},
    {'reference':'kernel-uek-tools-libs-4.14.35-1902.303.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-4.14.35'},
    {'reference':'kernel-uek-tools-libs-devel-4.14.35-1902.303.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-devel-4.14.35'},
    {'reference':'perf-4.14.35-1902.303.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-4.14.35-1902.303.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-debug / kernel-uek-debug-devel / etc');
}
