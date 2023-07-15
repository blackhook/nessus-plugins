#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2020:4431.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157698);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2019-9455",
    "CVE-2019-9458",
    "CVE-2019-12614",
    "CVE-2019-15917",
    "CVE-2019-15925",
    "CVE-2019-16231",
    "CVE-2019-16233",
    "CVE-2019-18808",
    "CVE-2019-18809",
    "CVE-2019-19046",
    "CVE-2019-19056",
    "CVE-2019-19062",
    "CVE-2019-19063",
    "CVE-2019-19068",
    "CVE-2019-19072",
    "CVE-2019-19319",
    "CVE-2019-19332",
    "CVE-2019-19447",
    "CVE-2019-19524",
    "CVE-2019-19533",
    "CVE-2019-19537",
    "CVE-2019-19543",
    "CVE-2019-19602",
    "CVE-2019-19767",
    "CVE-2019-19770",
    "CVE-2019-20054",
    "CVE-2019-20636",
    "CVE-2020-0305",
    "CVE-2020-0444",
    "CVE-2020-8647",
    "CVE-2020-8648",
    "CVE-2020-8649",
    "CVE-2020-10732",
    "CVE-2020-10751",
    "CVE-2020-10773",
    "CVE-2020-10774",
    "CVE-2020-10942",
    "CVE-2020-11565",
    "CVE-2020-11668",
    "CVE-2020-12465",
    "CVE-2020-12655",
    "CVE-2020-12659",
    "CVE-2020-12770",
    "CVE-2020-12826",
    "CVE-2020-14381",
    "CVE-2020-25641"
  );
  script_xref(name:"ALSA", value:"2020:4431");

  script_name(english:"AlmaLinux 8 : kernel (ALSA-2020:4431)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2020:4431 advisory.

  - In the Android kernel in the video driver there is a kernel pointer leak due to a WARN_ON statement. This
    could lead to local information disclosure with System execution privileges needed. User interaction is
    not needed for exploitation. (CVE-2019-9455)

  - In the Android kernel in the video driver there is a use after free due to a race condition. This could
    lead to local escalation of privilege with no additional execution privileges needed. User interaction is
    not needed for exploitation. (CVE-2019-9458)

  - An issue was discovered in dlpar_parse_cc_property in arch/powerpc/platforms/pseries/dlpar.c in the Linux
    kernel through 5.1.6. There is an unchecked kstrdup of prop->name, which might allow an attacker to cause
    a denial of service (NULL pointer dereference and system crash). (CVE-2019-12614)

  - An issue was discovered in the Linux kernel before 5.0.5. There is a use-after-free issue when
    hci_uart_register_dev() fails in hci_uart_set_proto() in drivers/bluetooth/hci_ldisc.c. (CVE-2019-15917)

  - An issue was discovered in the Linux kernel before 5.2.3. An out of bounds access exists in the function
    hclge_tm_schd_mode_vnet_base_cfg in the file drivers/net/ethernet/hisilicon/hns3/hns3pf/hclge_tm.c.
    (CVE-2019-15925)

  - drivers/net/fjes/fjes_main.c in the Linux kernel 5.2.14 does not check the alloc_workqueue return value,
    leading to a NULL pointer dereference. (CVE-2019-16231)

  - drivers/scsi/qla2xxx/qla_os.c in the Linux kernel 5.2.14 does not check the alloc_workqueue return value,
    leading to a NULL pointer dereference. (CVE-2019-16233)

  - A memory leak in the ccp_run_sha_cmd() function in drivers/crypto/ccp/ccp-ops.c in the Linux kernel
    through 5.3.9 allows attackers to cause a denial of service (memory consumption), aka CID-128c66429247.
    (CVE-2019-18808)

  - A memory leak in the af9005_identify_state() function in drivers/media/usb/dvb-usb/af9005.c in the Linux
    kernel through 5.3.9 allows attackers to cause a denial of service (memory consumption), aka
    CID-2289adbfa559. (CVE-2019-18809)

  - ** DISPUTED ** A memory leak in the __ipmi_bmc_register() function in drivers/char/ipmi/ipmi_msghandler.c
    in the Linux kernel through 5.3.11 allows attackers to cause a denial of service (memory consumption) by
    triggering ida_simple_get() failure, aka CID-4aa7afb0ee20. NOTE: third parties dispute the relevance of
    this because an attacker cannot realistically control this failure at probe time. (CVE-2019-19046)

  - A memory leak in the mwifiex_pcie_alloc_cmdrsp_buf() function in
    drivers/net/wireless/marvell/mwifiex/pcie.c in the Linux kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering mwifiex_map_pci_memory() failures, aka CID-
    db8fd2cde932. (CVE-2019-19056)

  - A memory leak in the crypto_report() function in crypto/crypto_user_base.c in the Linux kernel through
    5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering
    crypto_report_alg() failures, aka CID-ffdde5932042. (CVE-2019-19062)

  - Two memory leaks in the rtl_usb_probe() function in drivers/net/wireless/realtek/rtlwifi/usb.c in the
    Linux kernel through 5.3.11 allow attackers to cause a denial of service (memory consumption), aka
    CID-3f9361695113. (CVE-2019-19063)

  - A memory leak in the rtl8xxxu_submit_int_urb() function in
    drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu_core.c in the Linux kernel through 5.3.11 allows attackers
    to cause a denial of service (memory consumption) by triggering usb_submit_urb() failures, aka
    CID-a2cdd07488e6. (CVE-2019-19068)

  - A memory leak in the predicate_parse() function in kernel/trace/trace_events_filter.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of service (memory consumption), aka CID-96c5c6e6a5b6.
    (CVE-2019-19072)

  - In the Linux kernel before 5.2, a setxattr operation, after a mount of a crafted ext4 image, can cause a
    slab-out-of-bounds write access because of an ext4_xattr_set_entry use-after-free in fs/ext4/xattr.c when
    a large old_size value is used in a memset call, aka CID-345c0dbf3a30. (CVE-2019-19319)

  - An out-of-bounds memory write issue was found in the Linux Kernel, version 3.13 through 5.4, in the way
    the Linux kernel's KVM hypervisor handled the 'KVM_GET_EMULATED_CPUID' ioctl(2) request to get CPUID
    features emulated by the KVM hypervisor. A user or process able to access the '/dev/kvm' device could use
    this flaw to crash the system, resulting in a denial of service. (CVE-2019-19332)

  - In the Linux kernel 5.0.21, mounting a crafted ext4 filesystem image, performing some operations, and
    unmounting can lead to a use-after-free in ext4_put_super in fs/ext4/super.c, related to dump_orphan_list
    in fs/ext4/super.c. (CVE-2019-19447)

  - In the Linux kernel before 5.3.12, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/input/ff-memless.c driver, aka CID-fa3a5a1880c9. (CVE-2019-19524)

  - In the Linux kernel before 5.3.4, there is an info-leak bug that can be caused by a malicious USB device
    in the drivers/media/usb/ttusb-dec/ttusb_dec.c driver, aka CID-a10feaf8c464. (CVE-2019-19533)

  - In the Linux kernel before 5.2.10, there is a race condition bug that can be caused by a malicious USB
    device in the USB character device driver layer, aka CID-303911cfc5b9. This affects
    drivers/usb/core/file.c. (CVE-2019-19537)

  - In the Linux kernel before 5.1.6, there is a use-after-free in serial_ir_init_module() in
    drivers/media/rc/serial_ir.c. (CVE-2019-19543)

  - fpregs_state_valid in arch/x86/include/asm/fpu/internal.h in the Linux kernel before 5.4.2, when GCC 9 is
    used, allows context-dependent attackers to cause a denial of service (memory corruption) or possibly have
    unspecified other impact because of incorrect fpu_fpregs_owner_ctx caching, as demonstrated by mishandling
    of signal-based non-cooperative preemption in Go 1.14 prereleases on amd64, aka CID-59c4bd853abc.
    (CVE-2019-19602)

  - The Linux kernel before 5.4.2 mishandles ext4_expand_extra_isize, as demonstrated by use-after-free errors
    in __ext4_expand_extra_isize and ext4_xattr_set_entry, related to fs/ext4/inode.c and fs/ext4/super.c, aka
    CID-4ea99936a163. (CVE-2019-19767)

  - ** DISPUTED ** In the Linux kernel 4.19.83, there is a use-after-free (read) in the debugfs_remove
    function in fs/debugfs/inode.c (which is used to remove a file or directory in debugfs that was previously
    created with a call to another debugfs function such as debugfs_create_file). NOTE: Linux kernel
    developers dispute this issue as not being an issue with debugfs, instead this is an issue with misuse of
    debugfs within blktrace. (CVE-2019-19770)

  - In the Linux kernel before 5.0.6, there is a NULL pointer dereference in drop_sysctl_table() in
    fs/proc/proc_sysctl.c, related to put_links, aka CID-23da9588037e. (CVE-2019-20054)

  - In the Linux kernel before 5.4.12, drivers/input/input.c has out-of-bounds writes via a crafted keycode
    table, as demonstrated by input_set_keycode, aka CID-cb222aed03d7. (CVE-2019-20636)

  - In cdev_get of char_dev.c, there is a possible use-after-free due to a race condition. This could lead to
    local escalation of privilege with System execution privileges needed. User interaction is not needed for
    exploitation.Product: AndroidVersions: Android-10Android ID: A-153467744 (CVE-2020-0305)

  - In audit_free_lsm_field of auditfilter.c, there is a possible bad kfree due to a logic error in
    audit_data_to_entry. This could lead to local escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-150693166References: Upstream kernel (CVE-2020-0444)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the vc_do_resize function in
    drivers/tty/vt/vt.c. (CVE-2020-8647)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the n_tty_receive_buf_common
    function in drivers/tty/n_tty.c. (CVE-2020-8648)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the vgacon_invert_region
    function in drivers/video/console/vgacon.c. (CVE-2020-8649)

  - A flaw was found in the Linux kernel's implementation of Userspace core dumps. This flaw allows an
    attacker with a local account to crash a trivial program and exfiltrate private kernel data.
    (CVE-2020-10732)

  - A flaw was found in the Linux kernels SELinux LSM hook implementation before version 5.7, where it
    incorrectly assumed that an skb would only contain a single netlink message. The hook would incorrectly
    only validate the first netlink message in the skb and allow or deny the rest of the messages within the
    skb with the granted permission without further processing. (CVE-2020-10751)

  - A stack information leak flaw was found in s390/s390x in the Linux kernel's memory manager functionality,
    where it incorrectly writes to the /proc/sys/vm/cmm_timeout file. This flaw allows a local user to see the
    kernel data. (CVE-2020-10773)

  - A memory disclosure flaw was found in the Linux kernel's versions before 4.18.0-193.el8 in the sysctl
    subsystem when reading the /proc/sys/kernel/rh_features file. This flaw allows a local user to read
    uninitialized values from the kernel memory. The highest threat from this vulnerability is to
    confidentiality. (CVE-2020-10774)

  - In the Linux kernel before 5.5.8, get_raw_socket in drivers/vhost/net.c lacks validation of an sk_family
    field, which might allow attackers to trigger kernel stack corruption via crafted system calls.
    (CVE-2020-10942)

  - ** DISPUTED ** An issue was discovered in the Linux kernel through 5.6.2. mpol_parse_str in mm/mempolicy.c
    has a stack-based out-of-bounds write because an empty nodelist is mishandled during mount option parsing,
    aka CID-aa9f7d5172fa. NOTE: Someone in the security community disagrees that this is a vulnerability
    because the issue is a bug in parsing mount options which can only be specified by a privileged user, so
    triggering the bug does not grant any powers not already held.. (CVE-2020-11565)

  - In the Linux kernel before 5.6.1, drivers/media/usb/gspca/xirlink_cit.c (aka the Xirlink camera USB
    driver) mishandles invalid descriptors, aka CID-a246b4d54770. (CVE-2020-11668)

  - An array overflow was discovered in mt76_add_fragment in drivers/net/wireless/mediatek/mt76/dma.c in the
    Linux kernel before 5.5.10, aka CID-b102f0c522cf. An oversized packet with too many rx fragments can
    corrupt memory of adjacent pages. (CVE-2020-12465)

  - An issue was discovered in xfs_agf_verify in fs/xfs/libxfs/xfs_alloc.c in the Linux kernel through 5.6.10.
    Attackers may trigger a sync of excessive duration via an XFS v5 image with crafted metadata, aka
    CID-d0c7feaf8767. (CVE-2020-12655)

  - An issue was discovered in the Linux kernel before 5.6.7. xdp_umem_reg in net/xdp/xdp_umem.c has an out-
    of-bounds write (by a user with the CAP_NET_ADMIN capability) because of a lack of headroom validation.
    (CVE-2020-12659)

  - An issue was discovered in the Linux kernel through 5.6.11. sg_write lacks an sg_remove_request call in a
    certain failure case, aka CID-83c6f2390040. (CVE-2020-12770)

  - A signal access-control issue was discovered in the Linux kernel before 5.6.5, aka CID-7395ea4e65c2.
    Because exec_id in include/linux/sched.h is only 32 bits, an integer overflow can interfere with a
    do_notify_parent protection mechanism. A child process can send an arbitrary signal to a parent process in
    a different security domain. Exploitation limitations include the amount of elapsed time before an integer
    overflow occurs, and the lack of scenarios where signals to a parent process present a substantial
    operational threat. (CVE-2020-12826)

  - A flaw was found in the Linux kernel's futex implementation. This flaw allows a local attacker to corrupt
    system memory or escalate their privileges when creating a futex on a filesystem that is about to be
    unmounted. The highest threat from this vulnerability is to confidentiality, integrity, as well as system
    availability. (CVE-2020-14381)

  - A flaw was found in the Linux kernel's implementation of biovecs in versions before 5.9-rc7. A zero-length
    biovec request issued by the block subsystem could cause the kernel to enter an infinite loop, causing a
    denial of service. This flaw allows a local attacker with basic privileges to issue requests to a block
    device, resulting in a denial of service. The highest threat from this vulnerability is to system
    availability. (CVE-2020-25641)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2020-4431.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12659");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-19770");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2019-9455', 'CVE-2019-9458', 'CVE-2019-12614', 'CVE-2019-15917', 'CVE-2019-15925', 'CVE-2019-16231', 'CVE-2019-16233', 'CVE-2019-18808', 'CVE-2019-18809', 'CVE-2019-19046', 'CVE-2019-19056', 'CVE-2019-19062', 'CVE-2019-19063', 'CVE-2019-19068', 'CVE-2019-19072', 'CVE-2019-19319', 'CVE-2019-19332', 'CVE-2019-19447', 'CVE-2019-19524', 'CVE-2019-19533', 'CVE-2019-19537', 'CVE-2019-19543', 'CVE-2019-19602', 'CVE-2019-19767', 'CVE-2019-19770', 'CVE-2019-20054', 'CVE-2019-20636', 'CVE-2020-0305', 'CVE-2020-0444', 'CVE-2020-8647', 'CVE-2020-8648', 'CVE-2020-8649', 'CVE-2020-10732', 'CVE-2020-10751', 'CVE-2020-10773', 'CVE-2020-10774', 'CVE-2020-10942', 'CVE-2020-11565', 'CVE-2020-11668', 'CVE-2020-12465', 'CVE-2020-12655', 'CVE-2020-12659', 'CVE-2020-12770', 'CVE-2020-12826', 'CVE-2020-14381', 'CVE-2020-25641');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ALSA-2020:4431');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}
var pkgs = [
    {'reference':'bpftool-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-whitelists-4.18.0-240.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / kernel-core / etc');
}
