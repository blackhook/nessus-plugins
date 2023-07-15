#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5845.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140499);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-14613",
    "CVE-2018-16884",
    "CVE-2019-3874",
    "CVE-2019-3900",
    "CVE-2019-5108",
    "CVE-2019-10638",
    "CVE-2019-10639",
    "CVE-2019-11487",
    "CVE-2019-14898",
    "CVE-2019-15218",
    "CVE-2019-16746",
    "CVE-2019-17075",
    "CVE-2019-17133",
    "CVE-2019-18885",
    "CVE-2019-19052",
    "CVE-2019-19063",
    "CVE-2019-19066",
    "CVE-2019-19073",
    "CVE-2019-19074",
    "CVE-2019-19078",
    "CVE-2019-19535",
    "CVE-2019-19922",
    "CVE-2019-20812",
    "CVE-2020-10751",
    "CVE-2020-10767",
    "CVE-2020-10769",
    "CVE-2020-10781",
    "CVE-2020-12114",
    "CVE-2020-12771",
    "CVE-2020-14331",
    "CVE-2020-16166",
    "CVE-2020-24394"
  );
  script_bugtraq_id(
    104917,
    106253,
    107488,
    108054,
    108076,
    109092
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Linux 7 : Unbreakable Enterprise kernel (ELSA-2020-5845)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-5845 advisory.

  - A flaw was found in the Linux kernel's NFS41+ subsystem. NFS41+ shares mounted in different network
    namespaces at the same time can make bc_svc_process() use wrong back-channel IDs and cause a use-after-
    free vulnerability. Thus a malicious container user can cause a host kernel memory corruption and a system
    panic. Due to the nature of the flaw, privilege escalation cannot be fully ruled out. (CVE-2018-16884)

  - An infinite loop issue was found in the vhost_net kernel module in Linux Kernel up to and including
    v5.1-rc6, while handling incoming packets in handle_rx(). It could occur if one end sends packets faster
    than the other end can process them. A guest user, maybe remote one, could use this flaw to stall the
    vhost_net kernel thread, resulting in a DoS scenario. (CVE-2019-3900)

  - The Linux kernel before 5.1-rc5 allows page->_refcount reference count overflow, with resultant use-after-
    free issues, if about 140 GiB of RAM exists. This is related to fs/fuse/dev.c, fs/pipe.c, fs/splice.c,
    include/linux/mm.h, include/linux/pipe_fs_i.h, kernel/trace/trace.c, mm/gup.c, and mm/hugetlb.c. It can
    occur with FUSE requests. (CVE-2019-11487)

  - In the Linux kernel before 5.1.7, a device can be tracked by an attacker using the IP ID values the kernel
    produces for connection-less protocols (e.g., UDP and ICMP). When such traffic is sent to multiple
    destination IP addresses, it is possible to obtain hash collisions (of indices to the counter array) and
    thereby obtain the hashing key (via enumeration). An attack may be conducted by hosting a crafted web page
    that uses WebRTC or gQUIC to force UDP traffic to attacker-controlled IP addresses. (CVE-2019-10638)

  - The SCTP socket buffer used by a userspace application is not accounted by the cgroups subsystem. An
    attacker can use this flaw to cause a denial of service attack. Kernel 3.10.x and 4.18.x branches are
    believed to be vulnerable. (CVE-2019-3874)

  - The fix for CVE-2019-11599, affecting the Linux kernel before 5.0.10 was not complete. A local user could
    use this flaw to obtain sensitive information, cause a denial of service, or possibly have other
    unspecified impacts by triggering a race condition with mmget_not_zero or get_task_mm calls.
    (CVE-2019-14898)

  - In the Linux kernel through 5.3.2, cfg80211_mgd_wext_giwessid in net/wireless/wext-sme.c does not reject a
    long SSID IE, leading to a Buffer Overflow. (CVE-2019-17133)

  - An issue was discovered in net/wireless/nl80211.c in the Linux kernel through 5.2.17. It does not check
    the length of variable elements in a beacon head, leading to a buffer overflow. (CVE-2019-16746)

  - The Linux kernel 4.x (starting from 4.1) and 5.x before 5.0.8 allows Information Exposure (partial kernel
    address disclosure), leading to a KASLR bypass. Specifically, it is possible to extract the KASLR kernel
    image offset using the IP ID values the kernel produces for connection-less protocols (e.g., UDP and
    ICMP). When such traffic is sent to multiple destination IP addresses, it is possible to obtain hash
    collisions (of indices to the counter array) and thereby obtain the hashing key (via enumeration). This
    key contains enough bits from a kernel address (of a static variable) so when the key is extracted (via
    enumeration), the offset of the kernel image is exposed. This attack can be carried out remotely, by the
    attacker forcing the target device to send UDP or ICMP (or certain other) traffic to attacker-controlled
    IP addresses. Forcing a server to send UDP traffic is trivial if the server is a DNS server. ICMP traffic
    is trivial if the server answers ICMP Echo requests (ping). For client targets, if the target visits the
    attacker's web page, then WebRTC or gQUIC can be used to force UDP traffic to attacker-controlled IP
    addresses. NOTE: this attack against KASLR became viable in 4.1 because IP ID generation was changed to
    have a dependency on an address associated with a network namespace. (CVE-2019-10639)

  - Memory leaks in drivers/net/wireless/ath/ath9k/htc_hst.c in the Linux kernel through 5.3.11 allow
    attackers to cause a denial of service (memory consumption) by triggering wait_for_completion_timeout()
    failures. This affects the htc_config_pipe_credits() function, the htc_setup_complete() function, and the
    htc_connect_service() function, aka CID-853acf7caf10. (CVE-2019-19073)

  - A memory leak in the ath9k_wmi_cmd() function in drivers/net/wireless/ath/ath9k/wmi.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of service (memory consumption), aka CID-728c1e2a05e4.
    (CVE-2019-19074)

  - kernel/sched/fair.c in the Linux kernel before 5.3.9, when cpu.cfs_quota_us is used (e.g., with
    Kubernetes), allows attackers to cause a denial of service against non-cpu-bound applications by
    generating a workload that triggers unwanted slice expiration, aka CID-de53fd7aedb1. (In other words,
    although this slice expiration would typically be seen with benign workloads, it is possible that an
    attacker could calculate how many stray requests are required to force an entire Kubernetes cluster into a
    low-performance state caused by slice expiration, and ensure that a DDoS attack sent that number of stray
    requests. An attack does not affect the stability of the kernel; it only causes mismanagement of
    application execution.) (CVE-2019-19922)

  - A flaw was found in the Linux kernel before 5.8-rc1 in the implementation of the Enhanced IBPB (Indirect
    Branch Prediction Barrier). The IBPB mitigation will be disabled when STIBP is not available or when the
    Enhanced Indirect Branch Restricted Speculation (IBRS) is available. This flaw allows a local attacker to
    perform a Spectre V2 style attack when this configuration is active. The highest threat from this
    vulnerability is to confidentiality. (CVE-2020-10767)

  - In the Linux kernel before 5.2.9, there is an info-leak bug that can be caused by a malicious USB device
    in the drivers/net/can/usb/peak_usb/pcan_usb_fd.c driver, aka CID-30a8beeb3042. (CVE-2019-19535)

  - An issue was discovered in the Linux kernel before 5.4.7. The prb_calc_retire_blk_tmo() function in
    net/packet/af_packet.c can result in a denial of service (CPU consumption and soft lockup) in a certain
    failure case involving TPACKET_V3, aka CID-b43d1f9f7067. (CVE-2019-20812)

  - A flaw was found in the Linux kernels implementation of the invert video code on VGA consoles when a
    local attacker attempts to resize the console, calling an ioctl VT_RESIZE, which causes an out-of-bounds
    write to occur. This flaw allows a local user with access to the VGA console to crash the system,
    potentially escalating their privileges on the system. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system availability. (CVE-2020-14331)

  - fs/btrfs/volumes.c in the Linux kernel before 5.1 allows a btrfs_verify_dev_extents NULL pointer
    dereference via a crafted btrfs image because fs_devices->devices is mishandled within find_device, aka
    CID-09ba3bc9dd15. (CVE-2019-18885)

  - In the Linux kernel before 5.7.8, fs/nfsd/vfs.c (in the NFS server) can set incorrect permissions on new
    filesystem objects when the filesystem lacks ACL support, aka CID-22cf8419f131. This occurs because the
    current umask is not considered. (CVE-2020-24394)

  - A flaw was found in the Linux Kernel before 5.8-rc6 in the ZRAM kernel module, where a user with a local
    account and the ability to read the /sys/class/zram-control/hot_add file can create ZRAM device nodes in
    the /dev/ directory. This read allocates kernel memory and is not accounted for a user that triggers the
    creation of that ZRAM device. With this vulnerability, continually reading the device may consume a large
    amount of system memory and cause the Out-of-Memory (OOM) killer to activate and terminate random
    userspace processes, possibly making the system inoperable. (CVE-2020-10781)

  - The Linux kernel through 5.7.11 allows remote attackers to make observations that help to obtain sensitive
    information about the internal state of the network RNG, aka CID-f227e3ec3b5c. This is related to
    drivers/char/random.c and kernel/time/timer.c. (CVE-2020-16166)

  - An issue was discovered in the Linux kernel through 4.17.10. There is an invalid pointer dereference in
    io_ctl_map_page() when mounting and operating a crafted btrfs image, because of a lack of block group item
    validation in check_leaf_item in fs/btrfs/tree-checker.c. (CVE-2018-14613)

  - A buffer over-read flaw was found in RH kernel versions before 5.0 in crypto_authenc_extractkeys in
    crypto/authenc.c in the IPsec Cryptographic algorithm's module, authenc. When a payload longer than 4
    bytes, and is not following 4-byte alignment boundary guidelines, it causes a buffer over-read threat,
    leading to a system crash. This flaw allows a local attacker with user privileges to cause a denial of
    service. (CVE-2020-10769)

  - A pivot_root race condition in fs/namespace.c in the Linux kernel 4.4.x before 4.4.221, 4.9.x before
    4.9.221, 4.14.x before 4.14.178, 4.19.x before 4.19.119, and 5.x before 5.3 allows local users to cause a
    denial of service (panic) by corrupting a mountpoint reference counter. (CVE-2020-12114)

  - A flaw was found in the Linux kernels SELinux LSM hook implementation before version 5.7, where it
    incorrectly assumed that an skb would only contain a single netlink message. The hook would incorrectly
    only validate the first netlink message in the skb and allow or deny the rest of the messages within the
    skb with the granted permission without further processing. (CVE-2020-10751)

  - An exploitable denial-of-service vulnerability exists in the Linux kernel prior to mainline 5.3. An
    attacker could exploit this vulnerability by triggering AP to send IAPP location updates for stations
    before the required authentication process has completed. This could lead to different denial-of-service
    scenarios, either by causing CAM table attacks, or by leading to traffic flapping if faking already
    existing clients in other nearby APs of the same wireless infrastructure. An attacker can forge
    Authentication and Association Request packets to trigger this vulnerability. (CVE-2019-5108)

  - An issue was discovered in write_tpt_entry in drivers/infiniband/hw/cxgb4/mem.c in the Linux kernel
    through 5.3.2. The cxgb4 driver is directly calling dma_map_single (a DMA function) from a stack variable.
    This could allow an attacker to trigger a Denial of Service, exploitable if this driver is used on an
    architecture for which this stack/DMA interaction has security relevance. (CVE-2019-17075)

  - An issue was discovered in the Linux kernel before 5.1.8. There is a NULL pointer dereference caused by a
    malicious USB device in the drivers/media/usb/siano/smsusb.c driver. (CVE-2019-15218)

  - A memory leak in the gs_can_open() function in drivers/net/can/usb/gs_usb.c in the Linux kernel before
    5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering usb_submit_urb()
    failures, aka CID-fb5be6a7b486. (CVE-2019-19052)

  - Two memory leaks in the rtl_usb_probe() function in drivers/net/wireless/realtek/rtlwifi/usb.c in the
    Linux kernel through 5.3.11 allow attackers to cause a denial of service (memory consumption), aka
    CID-3f9361695113. (CVE-2019-19063)

  - A memory leak in the bfad_im_get_stats() function in drivers/scsi/bfa/bfad_attr.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering
    bfa_port_get_stats() failures, aka CID-0e62395da2bd. (CVE-2019-19066)

  - A memory leak in the ath10k_usb_hif_tx_sg() function in drivers/net/wireless/ath/ath10k/usb.c in the Linux
    kernel through 5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering
    usb_submit_urb() failures, aka CID-b8d17e7d93d2. (CVE-2019-19078)

  - An issue was discovered in the Linux kernel through 5.6.11. btree_gc_coalesce in drivers/md/bcache/btree.c
    has a deadlock if a coalescing operation fails. (CVE-2020-12771)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-5845.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17133");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/11");

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
  var fixed_uptrack_levels = ['4.14.35-1902.306.2.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2020-5845');
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
    {'reference':'kernel-uek-4.14.35-1902.306.2.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.14.35'},
    {'reference':'kernel-uek-4.14.35-1902.306.2.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.14.35'},
    {'reference':'kernel-uek-debug-4.14.35-1902.306.2.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.14.35'},
    {'reference':'kernel-uek-debug-4.14.35-1902.306.2.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.14.35'},
    {'reference':'kernel-uek-debug-devel-4.14.35-1902.306.2.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.14.35'},
    {'reference':'kernel-uek-debug-devel-4.14.35-1902.306.2.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.14.35'},
    {'reference':'kernel-uek-devel-4.14.35-1902.306.2.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.14.35'},
    {'reference':'kernel-uek-devel-4.14.35-1902.306.2.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.14.35'},
    {'reference':'kernel-uek-doc-4.14.35-1902.306.2.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.14.35'},
    {'reference':'kernel-uek-headers-4.14.35-1902.306.2.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-4.14.35'},
    {'reference':'kernel-uek-tools-4.14.35-1902.306.2.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-4.14.35'},
    {'reference':'kernel-uek-tools-4.14.35-1902.306.2.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-4.14.35'},
    {'reference':'kernel-uek-tools-libs-4.14.35-1902.306.2.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-4.14.35'},
    {'reference':'kernel-uek-tools-libs-devel-4.14.35-1902.306.2.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-devel-4.14.35'},
    {'reference':'perf-4.14.35-1902.306.2.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-4.14.35-1902.306.2.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
