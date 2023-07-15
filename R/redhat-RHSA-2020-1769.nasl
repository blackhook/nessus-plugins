##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1769. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(136115);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2018-16871",
    "CVE-2019-8980",
    "CVE-2019-10639",
    "CVE-2019-15090",
    "CVE-2019-15099",
    "CVE-2019-15221",
    "CVE-2019-17053",
    "CVE-2019-17055",
    "CVE-2019-18805",
    "CVE-2019-19045",
    "CVE-2019-19047",
    "CVE-2019-19055",
    "CVE-2019-19057",
    "CVE-2019-19058",
    "CVE-2019-19059",
    "CVE-2019-19065",
    "CVE-2019-19073",
    "CVE-2019-19074",
    "CVE-2019-19077",
    "CVE-2019-19534",
    "CVE-2019-19768",
    "CVE-2019-19922",
    "CVE-2020-1749"
  );
  script_bugtraq_id(107120, 108547, 108768);
  script_xref(name:"RHSA", value:"2020:1769");

  script_name(english:"RHEL 8 : kernel (RHSA-2020:1769)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:1769 advisory.

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

  - kernel: buffer-overflow hardening in WiFi beacon validation code. (CVE-2019-16746)

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

  - kernel: triggering AP to send IAPP location updates for stations before the required authentication
    process has completed can lead to DoS (CVE-2019-5108)

  - kernel: memory leak in the kernel_read_file function in fs/exec.c allows to cause a denial of service
    (CVE-2019-8980)

  - kernel: use-after-free in cdev_put() when a PTP device is removed while it's chardev is open
    (CVE-2020-10690)

  - kernel: some ipv6 protocols not encrypted over ipsec tunnel (CVE-2020-1749)

  - kernel: use-after-free in i915_ppgtt_close in drivers/gpu/drm/i915/i915_gem_gtt.c (CVE-2020-7053)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-16871");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-5108");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8980");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10639");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-12819");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15090");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15099");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15221");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15223");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16234");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16746");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-17053");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-17055");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-18282");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-18805");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19045");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19047");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19055");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19057");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19058");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19059");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19065");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19067");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19073");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19074");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19077");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19532");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19534");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19768");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19922");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1749");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-7053");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10690");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1655162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1679972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1721962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1729933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1743526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1743560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1749974");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1749976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1758242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1758248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1771496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1774933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1774937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1774968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1774983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1774991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1781821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1783540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1786164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1789927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1792512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1795624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1796360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1809833");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1817141");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 120, 125, 190, 200, 250, 319, 400, 416, 440, 476, 772);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2018-16871', 'CVE-2019-5108', 'CVE-2019-8980', 'CVE-2019-10639', 'CVE-2019-12819', 'CVE-2019-15090', 'CVE-2019-15099', 'CVE-2019-15221', 'CVE-2019-15223', 'CVE-2019-16234', 'CVE-2019-16746', 'CVE-2019-17053', 'CVE-2019-17055', 'CVE-2019-18282', 'CVE-2019-18805', 'CVE-2019-19045', 'CVE-2019-19047', 'CVE-2019-19055', 'CVE-2019-19057', 'CVE-2019-19058', 'CVE-2019-19059', 'CVE-2019-19065', 'CVE-2019-19067', 'CVE-2019-19073', 'CVE-2019-19074', 'CVE-2019-19077', 'CVE-2019-19532', 'CVE-2019-19534', 'CVE-2019-19768', 'CVE-2019-19922', 'CVE-2020-1749', 'CVE-2020-7053', 'CVE-2020-10690');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2020:1769');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.2/x86_64/appstream/debug',
      'content/aus/rhel8/8.2/x86_64/appstream/os',
      'content/aus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.2/x86_64/baseos/debug',
      'content/aus/rhel8/8.2/x86_64/baseos/os',
      'content/aus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.2/ppc64le/appstream/os',
      'content/e4s/rhel8/8.2/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.2/ppc64le/baseos/os',
      'content/e4s/rhel8/8.2/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.2/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.2/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.2/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.2/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/sap/debug',
      'content/e4s/rhel8/8.2/ppc64le/sap/os',
      'content/e4s/rhel8/8.2/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/appstream/debug',
      'content/e4s/rhel8/8.2/x86_64/appstream/os',
      'content/e4s/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/baseos/debug',
      'content/e4s/rhel8/8.2/x86_64/baseos/os',
      'content/e4s/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.2/x86_64/highavailability/os',
      'content/e4s/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/sap/debug',
      'content/e4s/rhel8/8.2/x86_64/sap/os',
      'content/e4s/rhel8/8.2/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/appstream/debug',
      'content/eus/rhel8/8.2/aarch64/appstream/os',
      'content/eus/rhel8/8.2/aarch64/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/baseos/debug',
      'content/eus/rhel8/8.2/aarch64/baseos/os',
      'content/eus/rhel8/8.2/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.2/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.2/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/highavailability/debug',
      'content/eus/rhel8/8.2/aarch64/highavailability/os',
      'content/eus/rhel8/8.2/aarch64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/supplementary/debug',
      'content/eus/rhel8/8.2/aarch64/supplementary/os',
      'content/eus/rhel8/8.2/aarch64/supplementary/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/appstream/debug',
      'content/eus/rhel8/8.2/ppc64le/appstream/os',
      'content/eus/rhel8/8.2/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/baseos/debug',
      'content/eus/rhel8/8.2/ppc64le/baseos/os',
      'content/eus/rhel8/8.2/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.2/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.2/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/highavailability/debug',
      'content/eus/rhel8/8.2/ppc64le/highavailability/os',
      'content/eus/rhel8/8.2/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/resilientstorage/debug',
      'content/eus/rhel8/8.2/ppc64le/resilientstorage/os',
      'content/eus/rhel8/8.2/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/sap-solutions/debug',
      'content/eus/rhel8/8.2/ppc64le/sap-solutions/os',
      'content/eus/rhel8/8.2/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/sap/debug',
      'content/eus/rhel8/8.2/ppc64le/sap/os',
      'content/eus/rhel8/8.2/ppc64le/sap/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/supplementary/debug',
      'content/eus/rhel8/8.2/ppc64le/supplementary/os',
      'content/eus/rhel8/8.2/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel8/8.2/s390x/appstream/debug',
      'content/eus/rhel8/8.2/s390x/appstream/os',
      'content/eus/rhel8/8.2/s390x/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/s390x/baseos/debug',
      'content/eus/rhel8/8.2/s390x/baseos/os',
      'content/eus/rhel8/8.2/s390x/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/s390x/codeready-builder/debug',
      'content/eus/rhel8/8.2/s390x/codeready-builder/os',
      'content/eus/rhel8/8.2/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/s390x/highavailability/debug',
      'content/eus/rhel8/8.2/s390x/highavailability/os',
      'content/eus/rhel8/8.2/s390x/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/s390x/resilientstorage/debug',
      'content/eus/rhel8/8.2/s390x/resilientstorage/os',
      'content/eus/rhel8/8.2/s390x/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.2/s390x/sap/debug',
      'content/eus/rhel8/8.2/s390x/sap/os',
      'content/eus/rhel8/8.2/s390x/sap/source/SRPMS',
      'content/eus/rhel8/8.2/s390x/supplementary/debug',
      'content/eus/rhel8/8.2/s390x/supplementary/os',
      'content/eus/rhel8/8.2/s390x/supplementary/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/appstream/debug',
      'content/eus/rhel8/8.2/x86_64/appstream/os',
      'content/eus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/baseos/debug',
      'content/eus/rhel8/8.2/x86_64/baseos/os',
      'content/eus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/highavailability/debug',
      'content/eus/rhel8/8.2/x86_64/highavailability/os',
      'content/eus/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/sap/debug',
      'content/eus/rhel8/8.2/x86_64/sap/os',
      'content/eus/rhel8/8.2/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/supplementary/debug',
      'content/eus/rhel8/8.2/x86_64/supplementary/os',
      'content/eus/rhel8/8.2/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/appstream/debug',
      'content/tus/rhel8/8.2/x86_64/appstream/os',
      'content/tus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/baseos/debug',
      'content/tus/rhel8/8.2/x86_64/baseos/os',
      'content/tus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/highavailability/debug',
      'content/tus/rhel8/8.2/x86_64/highavailability/os',
      'content/tus/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/nfv/debug',
      'content/tus/rhel8/8.2/x86_64/nfv/os',
      'content/tus/rhel8/8.2/x86_64/nfv/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/rt/debug',
      'content/tus/rhel8/8.2/x86_64/rt/os',
      'content/tus/rhel8/8.2/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-abi-whitelists-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-core-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-cross-headers-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-core-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-extra-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-extra-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-193.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-193.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-193.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-193.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-193.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-193.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-4.18.0-193.el8', 'sp':'2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-core-4.18.0-193.el8', 'sp':'2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-devel-4.18.0-193.el8', 'sp':'2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-4.18.0-193.el8', 'sp':'2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-193.el8', 'sp':'2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-perf-4.18.0-193.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.4/x86_64/appstream/debug',
      'content/aus/rhel8/8.4/x86_64/appstream/os',
      'content/aus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.4/x86_64/baseos/debug',
      'content/aus/rhel8/8.4/x86_64/baseos/os',
      'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.4/ppc64le/appstream/os',
      'content/e4s/rhel8/8.4/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.4/ppc64le/baseos/os',
      'content/e4s/rhel8/8.4/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.4/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.4/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/sap/debug',
      'content/e4s/rhel8/8.4/ppc64le/sap/os',
      'content/e4s/rhel8/8.4/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/appstream/debug',
      'content/e4s/rhel8/8.4/x86_64/appstream/os',
      'content/e4s/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/baseos/debug',
      'content/e4s/rhel8/8.4/x86_64/baseos/os',
      'content/e4s/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.4/x86_64/highavailability/os',
      'content/e4s/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/sap/debug',
      'content/e4s/rhel8/8.4/x86_64/sap/os',
      'content/e4s/rhel8/8.4/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/appstream/debug',
      'content/eus/rhel8/8.4/aarch64/appstream/os',
      'content/eus/rhel8/8.4/aarch64/appstream/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/baseos/debug',
      'content/eus/rhel8/8.4/aarch64/baseos/os',
      'content/eus/rhel8/8.4/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.4/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.4/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/highavailability/debug',
      'content/eus/rhel8/8.4/aarch64/highavailability/os',
      'content/eus/rhel8/8.4/aarch64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/supplementary/debug',
      'content/eus/rhel8/8.4/aarch64/supplementary/os',
      'content/eus/rhel8/8.4/aarch64/supplementary/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/appstream/debug',
      'content/eus/rhel8/8.4/ppc64le/appstream/os',
      'content/eus/rhel8/8.4/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/baseos/debug',
      'content/eus/rhel8/8.4/ppc64le/baseos/os',
      'content/eus/rhel8/8.4/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/highavailability/debug',
      'content/eus/rhel8/8.4/ppc64le/highavailability/os',
      'content/eus/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/resilientstorage/debug',
      'content/eus/rhel8/8.4/ppc64le/resilientstorage/os',
      'content/eus/rhel8/8.4/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/sap-solutions/debug',
      'content/eus/rhel8/8.4/ppc64le/sap-solutions/os',
      'content/eus/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/sap/debug',
      'content/eus/rhel8/8.4/ppc64le/sap/os',
      'content/eus/rhel8/8.4/ppc64le/sap/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/supplementary/debug',
      'content/eus/rhel8/8.4/ppc64le/supplementary/os',
      'content/eus/rhel8/8.4/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel8/8.4/s390x/appstream/debug',
      'content/eus/rhel8/8.4/s390x/appstream/os',
      'content/eus/rhel8/8.4/s390x/appstream/source/SRPMS',
      'content/eus/rhel8/8.4/s390x/baseos/debug',
      'content/eus/rhel8/8.4/s390x/baseos/os',
      'content/eus/rhel8/8.4/s390x/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/s390x/codeready-builder/debug',
      'content/eus/rhel8/8.4/s390x/codeready-builder/os',
      'content/eus/rhel8/8.4/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/s390x/highavailability/debug',
      'content/eus/rhel8/8.4/s390x/highavailability/os',
      'content/eus/rhel8/8.4/s390x/highavailability/source/SRPMS',
      'content/eus/rhel8/8.4/s390x/resilientstorage/debug',
      'content/eus/rhel8/8.4/s390x/resilientstorage/os',
      'content/eus/rhel8/8.4/s390x/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.4/s390x/sap/debug',
      'content/eus/rhel8/8.4/s390x/sap/os',
      'content/eus/rhel8/8.4/s390x/sap/source/SRPMS',
      'content/eus/rhel8/8.4/s390x/supplementary/debug',
      'content/eus/rhel8/8.4/s390x/supplementary/os',
      'content/eus/rhel8/8.4/s390x/supplementary/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/appstream/debug',
      'content/eus/rhel8/8.4/x86_64/appstream/os',
      'content/eus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/baseos/debug',
      'content/eus/rhel8/8.4/x86_64/baseos/os',
      'content/eus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/highavailability/debug',
      'content/eus/rhel8/8.4/x86_64/highavailability/os',
      'content/eus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/sap/debug',
      'content/eus/rhel8/8.4/x86_64/sap/os',
      'content/eus/rhel8/8.4/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/supplementary/debug',
      'content/eus/rhel8/8.4/x86_64/supplementary/os',
      'content/eus/rhel8/8.4/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/appstream/debug',
      'content/tus/rhel8/8.4/x86_64/appstream/os',
      'content/tus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/baseos/debug',
      'content/tus/rhel8/8.4/x86_64/baseos/os',
      'content/tus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/highavailability/debug',
      'content/tus/rhel8/8.4/x86_64/highavailability/os',
      'content/tus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/nfv/debug',
      'content/tus/rhel8/8.4/x86_64/nfv/os',
      'content/tus/rhel8/8.4/x86_64/nfv/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/rt/debug',
      'content/tus/rhel8/8.4/x86_64/rt/os',
      'content/tus/rhel8/8.4/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-abi-whitelists-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-core-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-cross-headers-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-core-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-extra-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-extra-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-193.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-193.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-193.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-193.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-193.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-193.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-4.18.0-193.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-core-4.18.0-193.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-devel-4.18.0-193.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-4.18.0-193.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-193.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-perf-4.18.0-193.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.6/x86_64/appstream/debug',
      'content/aus/rhel8/8.6/x86_64/appstream/os',
      'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.6/x86_64/baseos/debug',
      'content/aus/rhel8/8.6/x86_64/baseos/os',
      'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.6/ppc64le/appstream/os',
      'content/e4s/rhel8/8.6/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.6/ppc64le/baseos/os',
      'content/e4s/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/sap/debug',
      'content/e4s/rhel8/8.6/ppc64le/sap/os',
      'content/e4s/rhel8/8.6/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/appstream/debug',
      'content/e4s/rhel8/8.6/x86_64/appstream/os',
      'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/baseos/debug',
      'content/e4s/rhel8/8.6/x86_64/baseos/os',
      'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.6/x86_64/highavailability/os',
      'content/e4s/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sap/debug',
      'content/e4s/rhel8/8.6/x86_64/sap/os',
      'content/e4s/rhel8/8.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/appstream/debug',
      'content/eus/rhel8/8.6/aarch64/appstream/os',
      'content/eus/rhel8/8.6/aarch64/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/baseos/debug',
      'content/eus/rhel8/8.6/aarch64/baseos/os',
      'content/eus/rhel8/8.6/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/highavailability/debug',
      'content/eus/rhel8/8.6/aarch64/highavailability/os',
      'content/eus/rhel8/8.6/aarch64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/supplementary/debug',
      'content/eus/rhel8/8.6/aarch64/supplementary/os',
      'content/eus/rhel8/8.6/aarch64/supplementary/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/appstream/debug',
      'content/eus/rhel8/8.6/ppc64le/appstream/os',
      'content/eus/rhel8/8.6/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/baseos/debug',
      'content/eus/rhel8/8.6/ppc64le/baseos/os',
      'content/eus/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/highavailability/debug',
      'content/eus/rhel8/8.6/ppc64le/highavailability/os',
      'content/eus/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/debug',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/os',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/debug',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/os',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/sap/debug',
      'content/eus/rhel8/8.6/ppc64le/sap/os',
      'content/eus/rhel8/8.6/ppc64le/sap/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/supplementary/debug',
      'content/eus/rhel8/8.6/ppc64le/supplementary/os',
      'content/eus/rhel8/8.6/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel8/8.6/s390x/appstream/debug',
      'content/eus/rhel8/8.6/s390x/appstream/os',
      'content/eus/rhel8/8.6/s390x/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/s390x/baseos/debug',
      'content/eus/rhel8/8.6/s390x/baseos/os',
      'content/eus/rhel8/8.6/s390x/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/s390x/codeready-builder/debug',
      'content/eus/rhel8/8.6/s390x/codeready-builder/os',
      'content/eus/rhel8/8.6/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/s390x/highavailability/debug',
      'content/eus/rhel8/8.6/s390x/highavailability/os',
      'content/eus/rhel8/8.6/s390x/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/s390x/resilientstorage/debug',
      'content/eus/rhel8/8.6/s390x/resilientstorage/os',
      'content/eus/rhel8/8.6/s390x/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.6/s390x/sap/debug',
      'content/eus/rhel8/8.6/s390x/sap/os',
      'content/eus/rhel8/8.6/s390x/sap/source/SRPMS',
      'content/eus/rhel8/8.6/s390x/supplementary/debug',
      'content/eus/rhel8/8.6/s390x/supplementary/os',
      'content/eus/rhel8/8.6/s390x/supplementary/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/appstream/debug',
      'content/eus/rhel8/8.6/x86_64/appstream/os',
      'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/baseos/debug',
      'content/eus/rhel8/8.6/x86_64/baseos/os',
      'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/highavailability/debug',
      'content/eus/rhel8/8.6/x86_64/highavailability/os',
      'content/eus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sap/debug',
      'content/eus/rhel8/8.6/x86_64/sap/os',
      'content/eus/rhel8/8.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/supplementary/debug',
      'content/eus/rhel8/8.6/x86_64/supplementary/os',
      'content/eus/rhel8/8.6/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/appstream/debug',
      'content/tus/rhel8/8.6/x86_64/appstream/os',
      'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/baseos/debug',
      'content/tus/rhel8/8.6/x86_64/baseos/os',
      'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/highavailability/debug',
      'content/tus/rhel8/8.6/x86_64/highavailability/os',
      'content/tus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/rt/os',
      'content/tus/rhel8/8.6/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-abi-whitelists-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-core-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-cross-headers-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-core-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-extra-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-extra-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-193.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-193.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-193.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-193.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-193.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-193.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-4.18.0-193.el8', 'sp':'6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-core-4.18.0-193.el8', 'sp':'6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-devel-4.18.0-193.el8', 'sp':'6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-4.18.0-193.el8', 'sp':'6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-193.el8', 'sp':'6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-perf-4.18.0-193.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8/aarch64/appstream/debug',
      'content/dist/rhel8/8/aarch64/appstream/os',
      'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8/aarch64/baseos/debug',
      'content/dist/rhel8/8/aarch64/baseos/os',
      'content/dist/rhel8/8/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8/aarch64/codeready-builder/os',
      'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/aarch64/highavailability/debug',
      'content/dist/rhel8/8/aarch64/highavailability/os',
      'content/dist/rhel8/8/aarch64/highavailability/source/SRPMS',
      'content/dist/rhel8/8/aarch64/supplementary/debug',
      'content/dist/rhel8/8/aarch64/supplementary/os',
      'content/dist/rhel8/8/aarch64/supplementary/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/appstream/debug',
      'content/dist/rhel8/8/ppc64le/appstream/os',
      'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/baseos/debug',
      'content/dist/rhel8/8/ppc64le/baseos/os',
      'content/dist/rhel8/8/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/highavailability/debug',
      'content/dist/rhel8/8/ppc64le/highavailability/os',
      'content/dist/rhel8/8/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/resilientstorage/debug',
      'content/dist/rhel8/8/ppc64le/resilientstorage/os',
      'content/dist/rhel8/8/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/sap-solutions/debug',
      'content/dist/rhel8/8/ppc64le/sap-solutions/os',
      'content/dist/rhel8/8/ppc64le/sap-solutions/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/sap/debug',
      'content/dist/rhel8/8/ppc64le/sap/os',
      'content/dist/rhel8/8/ppc64le/sap/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/supplementary/debug',
      'content/dist/rhel8/8/ppc64le/supplementary/os',
      'content/dist/rhel8/8/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel8/8/s390x/appstream/debug',
      'content/dist/rhel8/8/s390x/appstream/os',
      'content/dist/rhel8/8/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8/s390x/baseos/debug',
      'content/dist/rhel8/8/s390x/baseos/os',
      'content/dist/rhel8/8/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8/s390x/codeready-builder/debug',
      'content/dist/rhel8/8/s390x/codeready-builder/os',
      'content/dist/rhel8/8/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/s390x/highavailability/debug',
      'content/dist/rhel8/8/s390x/highavailability/os',
      'content/dist/rhel8/8/s390x/highavailability/source/SRPMS',
      'content/dist/rhel8/8/s390x/resilientstorage/debug',
      'content/dist/rhel8/8/s390x/resilientstorage/os',
      'content/dist/rhel8/8/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/s390x/sap/debug',
      'content/dist/rhel8/8/s390x/sap/os',
      'content/dist/rhel8/8/s390x/sap/source/SRPMS',
      'content/dist/rhel8/8/s390x/supplementary/debug',
      'content/dist/rhel8/8/s390x/supplementary/os',
      'content/dist/rhel8/8/s390x/supplementary/source/SRPMS',
      'content/dist/rhel8/8/x86_64/appstream/debug',
      'content/dist/rhel8/8/x86_64/appstream/os',
      'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8/x86_64/baseos/debug',
      'content/dist/rhel8/8/x86_64/baseos/os',
      'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/x86_64/highavailability/debug',
      'content/dist/rhel8/8/x86_64/highavailability/os',
      'content/dist/rhel8/8/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel8/8/x86_64/nfv/debug',
      'content/dist/rhel8/8/x86_64/nfv/os',
      'content/dist/rhel8/8/x86_64/nfv/source/SRPMS',
      'content/dist/rhel8/8/x86_64/resilientstorage/debug',
      'content/dist/rhel8/8/x86_64/resilientstorage/os',
      'content/dist/rhel8/8/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/x86_64/rt/debug',
      'content/dist/rhel8/8/x86_64/rt/os',
      'content/dist/rhel8/8/x86_64/rt/source/SRPMS',
      'content/dist/rhel8/8/x86_64/sap-solutions/debug',
      'content/dist/rhel8/8/x86_64/sap-solutions/os',
      'content/dist/rhel8/8/x86_64/sap-solutions/source/SRPMS',
      'content/dist/rhel8/8/x86_64/sap/debug',
      'content/dist/rhel8/8/x86_64/sap/os',
      'content/dist/rhel8/8/x86_64/sap/source/SRPMS',
      'content/dist/rhel8/8/x86_64/supplementary/debug',
      'content/dist/rhel8/8/x86_64/supplementary/os',
      'content/dist/rhel8/8/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-abi-whitelists-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-core-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-cross-headers-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-core-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-extra-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-extra-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-193.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-193.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-193.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-193.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-4.18.0-193.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-core-4.18.0-193.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-devel-4.18.0-193.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-4.18.0-193.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-193.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-perf-4.18.0-193.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp']) && !enterprise_linux_flag) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / kernel-core / etc');
}
