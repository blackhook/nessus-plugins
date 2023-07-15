#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2021:4356. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155145);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/11");

  script_cve_id(
    "CVE-2019-14615",
    "CVE-2020-0427",
    "CVE-2020-24502",
    "CVE-2020-24503",
    "CVE-2020-24504",
    "CVE-2020-24586",
    "CVE-2020-24587",
    "CVE-2020-24588",
    "CVE-2020-26139",
    "CVE-2020-26140",
    "CVE-2020-26141",
    "CVE-2020-26143",
    "CVE-2020-26144",
    "CVE-2020-26145",
    "CVE-2020-26146",
    "CVE-2020-26147",
    "CVE-2020-27777",
    "CVE-2020-29368",
    "CVE-2020-29660",
    "CVE-2020-36158",
    "CVE-2020-36312",
    "CVE-2020-36386",
    "CVE-2021-0129",
    "CVE-2021-3348",
    "CVE-2021-3489",
    "CVE-2021-3564",
    "CVE-2021-3573",
    "CVE-2021-3600",
    "CVE-2021-3635",
    "CVE-2021-3659",
    "CVE-2021-3679",
    "CVE-2021-3732",
    "CVE-2021-20194",
    "CVE-2021-20239",
    "CVE-2021-23133",
    "CVE-2021-28950",
    "CVE-2021-28971",
    "CVE-2021-29155",
    "CVE-2021-29646",
    "CVE-2021-29650",
    "CVE-2021-31440",
    "CVE-2021-31829",
    "CVE-2021-31916",
    "CVE-2021-33033",
    "CVE-2021-33200"
  );
  script_xref(name:"RHSA", value:"2021:4356");
  script_xref(name:"IAVA", value:"2021-A-0223-S");
  script_xref(name:"IAVA", value:"2021-A-0222-S");

  script_name(english:"CentOS 8 : kernel (CESA-2021:4356)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2021:4356 advisory.

  - kernel: Intel graphics card information leak. (CVE-2019-14615)

  - kernel: out-of-bounds reads in pinctrl subsystem. (CVE-2020-0427)

  - kernel: Improper input validation in some Intel(R) Ethernet E810 Adapter drivers (CVE-2020-24502)

  - kernel: Insufficient access control in some Intel(R) Ethernet E810 Adapter drivers (CVE-2020-24503)

  - kernel: Uncontrolled resource consumption in some Intel(R) Ethernet E810 Adapter drivers (CVE-2020-24504)

  - kernel: Fragmentation cache not cleared on reconnection (CVE-2020-24586)

  - kernel: Reassembling fragments encrypted under different keys (CVE-2020-24587)

  - kernel: wifi frame payload being parsed incorrectly as an L2 frame (CVE-2020-24588)

  - kernel: Forwarding EAPOL from unauthenticated wifi client (CVE-2020-26139)

  - kernel: accepting plaintext data frames in protected networks (CVE-2020-26140)

  - kernel: not verifying TKIP MIC of fragmented frames (CVE-2020-26141)

  - kernel: accepting fragmented plaintext frames in protected networks (CVE-2020-26143)

  - kernel: accepting unencrypted A-MSDU frames that start with RFC1042 header (CVE-2020-26144)

  - kernel: accepting plaintext broadcast fragments as full frames (CVE-2020-26145)

  - kernel: reassembling encrypted fragments with non-consecutive packet numbers (CVE-2020-26146)

  - kernel: reassembling mixed encrypted/plaintext fragments (CVE-2020-26147)

  - kernel: powerpc: RTAS calls can be used to compromise kernel integrity (CVE-2020-27777)

  - kernel: the copy-on-write implementation can grant unintended write access because of a race condition in
    a THP mapcount check (CVE-2020-29368)

  - kernel: locking inconsistency in drivers/tty/tty_io.c and drivers/tty/tty_jobctrl.c can lead to a read-
    after-free (CVE-2020-29660)

  - kernel: buffer overflow in mwifiex_cmd_802_11_ad_hoc_start function in
    drivers/net/wireless/marvell/mwifiex/join.c via a long SSID value (CVE-2020-36158)

  - kernel: memory leak upon a kmalloc failure in kvm_io_bus_unregister_dev function in virt/kvm/kvm_main.c
    (CVE-2020-36312)

  - kernel: slab out-of-bounds read in hci_extended_inquiry_result_evt() in net/bluetooth/hci_event.c
    (CVE-2020-36386)

  - kernel: Improper access control in BlueZ may allow information disclosure vulnerability. (CVE-2021-0129)

  - kernel: heap overflow in __cgroup_bpf_run_filter_getsockopt() (CVE-2021-20194)

  - kernel: setsockopt System Call Untrusted Pointer Dereference Information Disclosure (CVE-2021-20239)

  - kernel: Race condition in sctp_destroy_sock list_del (CVE-2021-23133)

  - kernel: fuse: stall on CPU can occur because a retry loop continually finds the same bad inode
    (CVE-2021-28950)

  - kernel: System crash in intel_pmu_drain_pebs_nhm in arch/x86/events/intel/ds.c (CVE-2021-28971)

  - kernel: protection for sequences of pointer arithmetic operations against speculatively out-of-bounds
    loads can be bypassed to leak content of kernel memory (CVE-2021-29155)

  - kernel: improper input validation in tipc_nl_retrieve_key function in net/tipc/node.c (CVE-2021-29646)

  - kernel: lack a full memory barrier upon the assignment of a new table value in net/netfilter/x_tables.c
    and include/linux/netfilter/x_tables.h may lead to DoS (CVE-2021-29650)

  - kernel: local escalation of privileges in handling of eBPF programs (CVE-2021-31440)

  - kernel: protection of stack pointer against speculative pointer arithmetic can be bypassed to leak content
    of kernel memory (CVE-2021-31829)

  - kernel: out of bounds array access in drivers/md/dm-ioctl.c (CVE-2021-31916)

  - kernel: use-after-free in cipso_v4_genopt in net/ipv4/cipso_ipv4.c (CVE-2021-33033)

  - kernel: out-of-bounds reads and writes due to enforcing incorrect limits for pointer arithmetic operations
    by BPF verifier (CVE-2021-33200)

  - kernel: Use-after-free in ndb_queue_rq() in drivers/block/nbd.c (CVE-2021-3348)

  - kernel: Linux kernel eBPF RINGBUF map oversized allocation (CVE-2021-3489)

  - kernel: double free in bluetooth subsystem when the HCI device initialization fails (CVE-2021-3564)

  - kernel: use-after-free in function hci_sock_bound_ioctl() (CVE-2021-3573)

  - kernel: eBPF 32-bit source register truncation on div/mod (CVE-2021-3600)

  - kernel: flowtable list del corruption with kernel BUG at lib/list_debug.c:50 (CVE-2021-3635)

  - kernel: NULL pointer dereference in llsec_key_alloc() in net/mac802154/llsec.c (CVE-2021-3659)

  - kernel: DoS in rb_per_cpu_empty() (CVE-2021-3679)

  - kernel: overlayfs: Mounting overlayfs inside an unprivileged user namespace can reveal files
    (CVE-2021-3732)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:4356");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3489");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-stablelists");
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
  script_set_attribute(attribute:"stig_severity", value:"I");
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
var release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
var os_ver = os_ver[1];
if ('CentOS Stream' >!< release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2019-14615', 'CVE-2020-0427', 'CVE-2020-24502', 'CVE-2020-24503', 'CVE-2020-24504', 'CVE-2020-24586', 'CVE-2020-24587', 'CVE-2020-24588', 'CVE-2020-26139', 'CVE-2020-26140', 'CVE-2020-26141', 'CVE-2020-26143', 'CVE-2020-26144', 'CVE-2020-26145', 'CVE-2020-26146', 'CVE-2020-26147', 'CVE-2020-27777', 'CVE-2020-29368', 'CVE-2020-29660', 'CVE-2020-36158', 'CVE-2020-36312', 'CVE-2020-36386', 'CVE-2021-0129', 'CVE-2021-3348', 'CVE-2021-3489', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3600', 'CVE-2021-3635', 'CVE-2021-3659', 'CVE-2021-3679', 'CVE-2021-3732', 'CVE-2021-20194', 'CVE-2021-20239', 'CVE-2021-23133', 'CVE-2021-28950', 'CVE-2021-28971', 'CVE-2021-29155', 'CVE-2021-29646', 'CVE-2021-29650', 'CVE-2021-31440', 'CVE-2021-31829', 'CVE-2021-31916', 'CVE-2021-33033', 'CVE-2021-33200');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for CESA-2021:4356');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'reference':'bpftool-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-stablelists-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-stablelists-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / kernel-core / etc');
}
