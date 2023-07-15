##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2020:1769. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145850);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/23");

  script_cve_id(
    "CVE-2018-16871",
    "CVE-2019-8980",
    "CVE-2019-10639",
    "CVE-2019-12819",
    "CVE-2019-15090",
    "CVE-2019-15099",
    "CVE-2019-15221",
    "CVE-2019-15223",
    "CVE-2019-16234",
    "CVE-2019-17053",
    "CVE-2019-17055",
    "CVE-2019-18282",
    "CVE-2019-18805",
    "CVE-2019-19045",
    "CVE-2019-19047",
    "CVE-2019-19055",
    "CVE-2019-19057",
    "CVE-2019-19058",
    "CVE-2019-19059",
    "CVE-2019-19065",
    "CVE-2019-19067",
    "CVE-2019-19073",
    "CVE-2019-19074",
    "CVE-2019-19077",
    "CVE-2019-19532",
    "CVE-2019-19534",
    "CVE-2019-19768",
    "CVE-2019-19922",
    "CVE-2020-1749",
    "CVE-2020-7053",
    "CVE-2020-10690"
  );
  script_bugtraq_id(107120, 108547, 108768);
  script_xref(name:"RHSA", value:"2020:1769");

  script_name(english:"CentOS 8 : kernel (CESA-2020:1769)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:1769 advisory.

  - kernel: nfs: NULL pointer dereference due to an anomalized NFS message sequence (CVE-2018-16871)

  - Kernel: net: using kernel space address bits to derive IP ID may potentially break KASLR (CVE-2019-10639)

  - kernel: use-after-free in function __mdiobus_register() in drivers/net/phy/mdio_bus.c (CVE-2019-12819)

  - kernel: An out-of-bounds read in drivers/scsi/qedi/qedi_dbg.c leading to crash or information disclosure
    (CVE-2019-15090)

  - kernel: a NULL pointer dereference in drivers/net/wireless/ath/ath10k/usb.c leads to a crash
    (CVE-2019-15099)

  - kernel: Null pointer dereference in the sound/usb/line6/pcm.c (CVE-2019-15221)

  - kernel: Null pointer dereference in the sound/usb/line6/driver.c (CVE-2019-15223)

  - kernel: null pointer dereference in drivers/net/wireless/intel/iwlwifi/pcie/trans.c (CVE-2019-16234)

  - kernel: unprivileged users able to create RAW sockets in AF_IEEE802154 network protocol (CVE-2019-17053)

  - kernel: unprivileged users able to create RAW sockets in AF_ISDN network protocol (CVE-2019-17055)

  - kernel: The flow_dissector feature allows device tracking (CVE-2019-18282)

  - kernel: integer overflow in tcp_ack_update_rtt in net/ipv4/tcp_input.c (CVE-2019-18805)

  - kernel: dos in mlx5_fpga_conn_create_cq() function in drivers/net/ethernet/mellanox/mlx5/core/fpga/conn.c
    (CVE-2019-19045)

  - kernel: dos in mlx5_fw_fatal_reporter_dump() function in drivers/net/ethernet/mellanox/mlx5/core/health.c
    (CVE-2019-19047)

  - kernel: memory leak in the nl80211_get_ftm_responder_stats() function in net/wireless/nl80211.c allows DoS
    (CVE-2019-19055)

  - kernel: Two memory leaks in the mwifiex_pcie_init_evt_ring() function in
    drivers/net/wireless/marvell/mwifiex/pcie.c allows for a DoS (CVE-2019-19057)

  - kernel: A memory leak in the alloc_sgtable() function in drivers/net/wireless/intel/iwlwifi/fw/dbg.c
    allows for a DoS (CVE-2019-19058)

  - kernel: Multiple memory leaks in the iwl_pcie_ctxt_info_gen3_init() function in
    drivers/net/wireless/intel/iwlwifi/pcie/ctxt-info-gen3.c allows for a DoS (CVE-2019-19059)

  - kernel: A memory leak in the sdma_init() function in drivers/infiniband/hw/hfi1/sdma.c allows for a DoS
    (CVE-2019-19065)

  - kernel: Four memory leaks in the acp_hw_init() function in drivers/gpu/drm/amd/amdgpu/amdgpu_acp.c allow
    for a DoS (CVE-2019-19067)

  - kernel: Memory leaks in drivers/net/wireless/ath/ath9k/htc_hst.c in the Linux kernel (DOS)
    (CVE-2019-19073)

  - kernel: a memory leak in the ath9k management function in allows local DoS (CVE-2019-19074)

  - kernel: memory leak in bnxt_re_create_srq function in drivers/infiniband/hw/bnxt_re/ib_verbs.c
    (CVE-2019-19077)

  - kernel: malicious USB devices can lead to multiple out-of-bounds write (CVE-2019-19532)

  - kernel: information leak bug caused by a malicious USB device in the
    drivers/net/can/usb/peak_usb/pcan_usb_core.c driver (CVE-2019-19534)

  - kernel: use-after-free in __blk_add_trace in kernel/trace/blktrace.c (CVE-2019-19768)

  - kernel: when cpu.cfs_quota_us is used allows attackers to cause a denial of service against non-cpu-bound
    applications (CVE-2019-19922)

  - kernel: memory leak in the kernel_read_file function in fs/exec.c allows to cause a denial of service
    (CVE-2019-8980)

  - kernel: use-after-free in cdev_put() when a PTP device is removed while it's chardev is open
    (CVE-2020-10690)

  - kernel: some ipv6 protocols not encrypted over ipsec tunnel (CVE-2020-1749)

  - kernel: use-after-free in i915_ppgtt_close in drivers/gpu/drm/i915/i915_gem_gtt.c (CVE-2020-7053)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1769");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-perf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2018-16871', 'CVE-2019-8980', 'CVE-2019-10639', 'CVE-2019-12819', 'CVE-2019-15090', 'CVE-2019-15099', 'CVE-2019-15221', 'CVE-2019-15223', 'CVE-2019-16234', 'CVE-2019-17053', 'CVE-2019-17055', 'CVE-2019-18282', 'CVE-2019-18805', 'CVE-2019-19045', 'CVE-2019-19047', 'CVE-2019-19055', 'CVE-2019-19057', 'CVE-2019-19058', 'CVE-2019-19059', 'CVE-2019-19065', 'CVE-2019-19067', 'CVE-2019-19073', 'CVE-2019-19074', 'CVE-2019-19077', 'CVE-2019-19532', 'CVE-2019-19534', 'CVE-2019-19768', 'CVE-2019-19922', 'CVE-2020-1749', 'CVE-2020-7053', 'CVE-2020-10690');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for CESA-2020:1769');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'reference':'bpftool-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-whitelists-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-whitelists-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / kernel-core / etc');
}
