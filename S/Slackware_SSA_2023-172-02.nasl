#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2023-172-02. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177495);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/22");

  script_cve_id(
    "CVE-2022-2196",
    "CVE-2022-3707",
    "CVE-2022-4269",
    "CVE-2022-4379",
    "CVE-2022-27672",
    "CVE-2022-48425",
    "CVE-2023-0459",
    "CVE-2023-1076",
    "CVE-2023-1077",
    "CVE-2023-1078",
    "CVE-2023-1079",
    "CVE-2023-1118",
    "CVE-2023-1281",
    "CVE-2023-1380",
    "CVE-2023-1513",
    "CVE-2023-1611",
    "CVE-2023-1670",
    "CVE-2023-1829",
    "CVE-2023-1855",
    "CVE-2023-1859",
    "CVE-2023-1989",
    "CVE-2023-1990",
    "CVE-2023-2002",
    "CVE-2023-2156",
    "CVE-2023-2162",
    "CVE-2023-2194",
    "CVE-2023-2235",
    "CVE-2023-2248",
    "CVE-2023-2269",
    "CVE-2023-2483",
    "CVE-2023-2985",
    "CVE-2023-23004",
    "CVE-2023-25012",
    "CVE-2023-26545",
    "CVE-2023-28466",
    "CVE-2023-30456",
    "CVE-2023-30772",
    "CVE-2023-31436",
    "CVE-2023-32233",
    "CVE-2023-32269",
    "CVE-2023-33203",
    "CVE-2023-33288",
    "CVE-2023-34256"
  );

  script_name(english:"Slackware Linux 15.0 kernel-generic  Multiple Vulnerabilities (SSA:2023-172-02)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to kernel-generic.");
  script_set_attribute(attribute:"description", value:
"The version of kernel-generic installed on the remote host is prior to 5.15.118 / 5.15.118_smp. It is, therefore,
affected by multiple vulnerabilities as referenced in the SSA:2023-172-02 advisory.

  - A regression exists in the Linux Kernel within KVM: nVMX that allowed for speculative execution attacks.
    L2 can carry out Spectre v2 attacks on L1 due to L1 thinking it doesn't need retpolines or IBPB after
    running L2 due to KVM (L0) advertising eIBRS support to L1. An attacker at L2 with code execution can
    execute code on an indirect branch on the host machine. We recommend upgrading to Kernel 6.2 or past
    commit 2e7eab81425a (CVE-2022-2196)

  - When SMT is enabled, certain AMD processors may speculatively execute instructions using a target from the
    sibling thread after an SMT mode switch potentially resulting in information disclosure. (CVE-2022-27672)

  - A double-free memory flaw was found in the Linux kernel. The Intel GVT-g graphics driver triggers VGA card
    system resource overload, causing a fail in the intel_gvt_dma_map_guest_page function. This issue could
    allow a local user to crash the system. (CVE-2022-3707)

  - A flaw was found in the Linux kernel Traffic Control (TC) subsystem. Using a specific networking
    configuration (redirecting egress packets to ingress using TC action mirred) a local unprivileged user
    could trigger a CPU soft lockup (ABBA deadlock) when the transport protocol in use (TCP or SCTP) does a
    retransmission, resulting in a denial of service condition. (CVE-2022-4269)

  - A use-after-free vulnerability was found in __nfs42_ssc_open() in fs/nfs/nfs4file.c in the Linux kernel.
    This flaw allows an attacker to conduct a remote denial (CVE-2022-4379)

  - In the Linux kernel through 6.2.7, fs/ntfs3/inode.c has an invalid kfree because it does not validate MFT
    flags before replaying logs. (CVE-2022-48425)

  - Copy_from_user on 64-bit versions of the Linux kernel does not implement the __uaccess_begin_nospec
    allowing a user to bypass the access_ok check and pass a kernel pointer to copy_from_user(). This would
    allow an attacker to leak information. We recommend upgrading beyond commit
    74e19ef0ff8061ef55957c3abd71614ef0f42f47 (CVE-2023-0459)

  - A flaw was found in the Linux Kernel. The tun/tap sockets have their socket UID hardcoded to 0 due to a
    type confusion in their initialization function. While it will be often correct, as tuntap devices require
    CAP_NET_ADMIN, it may not always be the case, e.g., a non-root user only having that capability. This
    would make tun/tap sockets being incorrectly treated in filtering/routing decisions, possibly bypassing
    network filters. (CVE-2023-1076)

  - In the Linux kernel, pick_next_rt_entity() may return a type confused entry, not detected by the BUG_ON
    condition, as the confused entry will not be NULL, but list_head.The buggy error condition would lead to a
    type confused entry with the list head,which would then be used as a type confused sched_rt_entity,causing
    memory corruption. (CVE-2023-1077)

  - A flaw was found in the Linux Kernel in RDS (Reliable Datagram Sockets) protocol. The
    rds_rm_zerocopy_callback() uses list_entry() on the head of a list causing a type confusion. Local user
    can trigger this with rds_message_put(). Type confusion leads to `struct rds_msg_zcopy_info *info`
    actually points to something else that is potentially controlled by local user. It is known how to trigger
    this, which causes an out of bounds access, and a lock corruption. (CVE-2023-1078)

  - A flaw was found in the Linux kernel. A use-after-free may be triggered in asus_kbd_backlight_set when
    plugging/disconnecting in a malicious USB device, which advertises itself as an Asus device. Similarly to
    the previous known CVE-2023-25012, but in asus devices, the work_struct may be scheduled by the LED
    controller while the device is disconnecting, triggering a use-after-free on the struct asus_kbd_leds *led
    structure. A malicious USB device may exploit the issue to cause memory corruption with controlled data.
    (CVE-2023-1079)

  - A flaw use after free in the Linux kernel integrated infrared receiver/transceiver driver was found in the
    way user detaching rc device. A local user could use this flaw to crash the system or potentially escalate
    their privileges on the system. (CVE-2023-1118)

  - Use After Free vulnerability in Linux kernel traffic control index filter (tcindex) allows Privilege
    Escalation. The imperfect hash area can be updated while packets are traversing, which will cause a use-
    after-free when 'tcf_exts_exec()' is called with the destroyed tcf_ext. A local attacker user can use this
    vulnerability to elevate its privileges to root. This issue affects Linux Kernel: from 4.14 before git
    commit ee059170b1f7e94e55fa6cadee544e176a6e59c2. (CVE-2023-1281)

  - A slab-out-of-bound read problem was found in brcmf_get_assoc_ies in
    drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c in the Linux Kernel. This issue could occur
    when assoc_info->req_len data is bigger than the size of the buffer, defined as WL_EXTRA_BUF_MAX, leading
    to a denial of service. (CVE-2023-1380)

  - A flaw was found in KVM. When calling the KVM_GET_DEBUGREGS ioctl, on 32-bit systems, there might be some
    uninitialized portions of the kvm_debugregs structure that could be copied to userspace, causing an
    information leak. (CVE-2023-1513)

  - A use-after-free flaw was found in btrfs_search_slot in fs/btrfs/ctree.c in btrfs in the Linux Kernel.This
    flaw allows an attacker to crash the system and possibly cause a kernel information lea (CVE-2023-1611)

  - A flaw use after free in the Linux kernel Xircom 16-bit PCMCIA (PC-card) Ethernet driver was found.A local
    user could use this flaw to crash the system or potentially escalate their privileges on the system.
    (CVE-2023-1670)

  - A use-after-free vulnerability in the Linux Kernel traffic control index filter (tcindex) can be exploited
    to achieve local privilege escalation. The tcindex_delete function which does not properly deactivate
    filters in case of a perfect hashes while deleting the underlying structure which can later lead to double
    freeing the structure. A local attacker user can use this vulnerability to elevate its privileges to root.
    We recommend upgrading past commit 8c710f75256bb3cf05ac7b1672c82b92c43f3d28. (CVE-2023-1829)

  - A use-after-free flaw was found in xgene_hwmon_remove in drivers/hwmon/xgene-hwmon.c in the Hardware
    Monitoring Linux Kernel Driver (xgene-hwmon). This flaw could allow a local attacker to crash the system
    due to a race problem. This vulnerability could even lead to a kernel information leak problem.
    (CVE-2023-1855)

  - A use-after-free flaw was found in xen_9pfs_front_removet in net/9p/trans_xen.c in Xen transport for 9pfs
    in the Linux Kernel. This flaw could allow a local attacker to crash the system due to a race problem,
    possibly leading to a kernel information leak. (CVE-2023-1859)

  - A use-after-free flaw was found in btsdio_remove in drivers\bluetooth\btsdio.c in the Linux Kernel. In
    this flaw, a call to btsdio_remove with an unfinished job, may cause a race problem leading to a UAF on
    hdev devices. (CVE-2023-1989)

  - A use-after-free flaw was found in ndlc_remove in drivers/nfc/st-nci/ndlc.c in the Linux Kernel. This flaw
    could allow an attacker to crash the system due to a race problem. (CVE-2023-1990)

  - A vulnerability was found in the HCI sockets implementation due to a missing capability check in
    net/bluetooth/hci_sock.c in the Linux Kernel. This flaw allows an attacker to unauthorized execution of
    management commands, compromising the confidentiality, integrity, and availability of Bluetooth
    communication. (CVE-2023-2002)

  - A flaw was found in the networking subsystem of the Linux kernel within the handling of the RPL protocol.
    This issue results from the lack of proper handling of user-supplied data, which can lead to an assertion
    failure. This may allow an unauthenticated remote attacker to create a denial of service condition on the
    system. (CVE-2023-2156)

  - A use-after-free vulnerability was found in iscsi_sw_tcp_session_create in drivers/scsi/iscsi_tcp.c in
    SCSI sub-component in the Linux Kernel. In this flaw an attacker could leak kernel internal information.
    (CVE-2023-2162)

  - An out-of-bounds write vulnerability was found in the Linux kernel's SLIMpro I2C device driver. The
    userspace data->block[0] variable was not capped to a number between 0-255 and was used as the size of a
    memcpy, possibly writing beyond the end of dma_buffer. This flaw could allow a local privileged user to
    crash the system or potentially achieve code execution. (CVE-2023-2194)

  - A use-after-free vulnerability in the Linux Kernel Performance Events system can be exploited to achieve
    local privilege escalation. The perf_group_detach function did not check the event's siblings'
    attach_state before calling add_event_to_groups(), but remove_on_exec made it possible to call
    list_del_event() on before detaching from their group, making it possible to use a dangling pointer
    causing a use-after-free vulnerability. We recommend upgrading past commit
    fd0815f632c24878e325821943edccc7fde947a2. (CVE-2023-2235)

  - ** REJECT ** This CVE ID has been rejected or withdrawn by its CVE Numbering Authority because it was the
    duplicate of CVE-2023-31436. (CVE-2023-2248)

  - A denial of service problem was found, due to a possible recursive locking scenario, resulting in a
    deadlock in table_clear in drivers/md/dm-ioctl.c in the Linux Kernel Device Mapper-Multipathing sub-
    component. (CVE-2023-2269)

  - In the Linux kernel before 5.19, drivers/gpu/drm/arm/malidp_planes.c misinterprets the get_sg_table return
    value (expects it to be NULL in the error case, whereas it is actually an error pointer). (CVE-2023-23004)

  - The Linux kernel through 6.1.9 has a Use-After-Free in bigben_remove in drivers/hid/hid-bigbenff.c via a
    crafted USB device because the LED controllers remain registered for too long. (CVE-2023-25012)

  - In the Linux kernel before 6.1.13, there is a double free in net/mpls/af_mpls.c upon an allocation failure
    (for registering the sysctl table under a new location) during the renaming of a device. (CVE-2023-26545)

  - do_tls_getsockopt in net/tls/tls_main.c in the Linux kernel through 6.2.6 lacks a lock_sock call, leading
    to a race condition (with a resultant use-after-free or NULL pointer dereference). (CVE-2023-28466)

  - A use after free flaw was found in hfsplus_put_super in fs/hfsplus/super.c in the Linux Kernel. This flaw
    could allow a local user to cause a denial of service problem. (CVE-2023-2985)

  - An issue was discovered in arch/x86/kvm/vmx/nested.c in the Linux kernel before 6.2.8. nVMX on x86_64
    lacks consistency checks for CR0 and CR4. (CVE-2023-30456)

  - The Linux kernel before 6.2.9 has a race condition and resultant use-after-free in
    drivers/power/supply/da9150-charger.c if a physically proximate attacker unplugs a device.
    (CVE-2023-30772)

  - qfq_change_class in net/sched/sch_qfq.c in the Linux kernel before 6.2.13 allows an out-of-bounds write
    because lmax can exceed QFQ_MIN_LMAX. (CVE-2023-31436)

  - In the Linux kernel through 6.3.1, a use-after-free in Netfilter nf_tables when processing batch requests
    can be abused to perform arbitrary read and write operations on kernel memory. Unprivileged local users
    can obtain root privileges. This occurs because anonymous sets are mishandled. (CVE-2023-32233)

  - An issue was discovered in the Linux kernel before 6.1.11. In net/netrom/af_netrom.c, there is a use-
    after-free because accept is also allowed for a successfully connected AF_NETROM socket. However, in order
    for an attacker to exploit this, the system must have netrom routing configured or the attacker must have
    the CAP_NET_ADMIN capability. (CVE-2023-32269)

  - The Linux kernel before 6.2.9 has a race condition and resultant use-after-free in
    drivers/net/ethernet/qualcomm/emac/emac.c if a physically proximate attacker unplugs an emac based device.
    (CVE-2023-33203)

  - An issue was discovered in the Linux kernel before 6.2.9. A use-after-free was found in bq24190_remove in
    drivers/power/supply/bq24190_charger.c. It could allow a local attacker to crash the system due to a race
    condition. (CVE-2023-33288)

  - ** DISPUTED ** An issue was discovered in the Linux kernel before 6.3.3. There is an out-of-bounds read in
    crc16 in lib/crc16.c when called from fs/ext4/super.c because ext4_group_desc_csum does not properly check
    an offset. NOTE: this is disputed by third parties because the kernel is not intended to defend against
    attackers with the stated When modifying the block device while it is mounted by the filesystem access.
    (CVE-2023-34256)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.816190
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b44ee412");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected kernel-generic package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1079");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2196");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '5.15.118', 'product' : 'kernel-generic', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '5.15.118', 'product' : 'kernel-huge', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '5.15.118', 'product' : 'kernel-modules', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '5.15.118_smp', 'product' : 'kernel-generic-smp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '5.15.118_smp', 'product' : 'kernel-huge-smp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '5.15.118_smp', 'product' : 'kernel-modules-smp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '5.15.118', 'product' : 'kernel-source', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'noarch' },
    { 'fixed_version' : '5.15.118_smp', 'product' : 'kernel-source', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'noarch' },
    { 'fixed_version' : '5.15.118', 'product' : 'kernel-headers', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86' },
    { 'fixed_version' : '5.15.118_smp', 'product' : 'kernel-headers', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86' },
    { 'fixed_version' : '5.15.118', 'product' : 'kernel-generic', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '5.15.118', 'product' : 'kernel-huge', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '5.15.118', 'product' : 'kernel-modules', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86_64' }
];

foreach constraint (constraints) {
    var pkg_arch = constraint['arch'];
    var arch = NULL;
    if (pkg_arch == "x86_64") {
        arch = pkg_arch;
    }
    if (slackware_check(osver:constraint['os_version'],
                        arch:arch,
                        pkgname:constraint['product'],
                        pkgver:constraint['fixed_version'],
                        pkgarch:pkg_arch,
                        pkgnum:constraint['service_pack'])) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
