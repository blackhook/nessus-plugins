#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3972-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155959);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-9517",
    "CVE-2018-13405",
    "CVE-2019-3874",
    "CVE-2019-3900",
    "CVE-2020-0429",
    "CVE-2020-3702",
    "CVE-2020-12770",
    "CVE-2021-0941",
    "CVE-2021-3542",
    "CVE-2021-3640",
    "CVE-2021-3653",
    "CVE-2021-3655",
    "CVE-2021-3656",
    "CVE-2021-3659",
    "CVE-2021-3679",
    "CVE-2021-3715",
    "CVE-2021-3732",
    "CVE-2021-3744",
    "CVE-2021-3752",
    "CVE-2021-3753",
    "CVE-2021-3759",
    "CVE-2021-3760",
    "CVE-2021-3764",
    "CVE-2021-3772",
    "CVE-2021-20322",
    "CVE-2021-22543",
    "CVE-2021-31916",
    "CVE-2021-34556",
    "CVE-2021-34981",
    "CVE-2021-35477",
    "CVE-2021-37159",
    "CVE-2021-37576",
    "CVE-2021-38160",
    "CVE-2021-38198",
    "CVE-2021-38204",
    "CVE-2021-40490",
    "CVE-2021-41864",
    "CVE-2021-42008",
    "CVE-2021-42252",
    "CVE-2021-42739"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3972-1");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2021:3972-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:3972-1 advisory.

  - The inode_init_owner function in fs/inode.c in the Linux kernel through 3.16 allows local users to create
    files with an unintended group ownership, in a scenario where a directory is SGID to a certain group and
    is writable by a user who is not a member of that group. Here, the non-member can trigger creation of a
    plain file whose group ownership is that group. The intended behavior was that the non-member can trigger
    creation of a directory (but not a plain file) whose group ownership is that group. The non-member can
    escalate privileges by making the plain file executable and SGID. (CVE-2018-13405)

  - In pppol2tp_connect, there is possible memory corruption due to a use after free. This could lead to local
    escalation of privilege with System execution privileges needed. User interaction is not needed for
    exploitation. Product: Android. Versions: Android kernel. Android ID: A-38159931. (CVE-2018-9517)

  - The SCTP socket buffer used by a userspace application is not accounted by the cgroups subsystem. An
    attacker can use this flaw to cause a denial of service attack. Kernel 3.10.x and 4.18.x branches are
    believed to be vulnerable. (CVE-2019-3874)

  - An infinite loop issue was found in the vhost_net kernel module in Linux Kernel up to and including
    v5.1-rc6, while handling incoming packets in handle_rx(). It could occur if one end sends packets faster
    than the other end can process them. A guest user, maybe remote one, could use this flaw to stall the
    vhost_net kernel thread, resulting in a DoS scenario. (CVE-2019-3900)

  - In l2tp_session_delete and related functions of l2tp_core.c, there is possible memory corruption due to a
    use after free. This could lead to local escalation of privilege with System execution privileges needed.
    User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-152735806 (CVE-2020-0429)

  - An issue was discovered in the Linux kernel through 5.6.11. sg_write lacks an sg_remove_request call in a
    certain failure case, aka CID-83c6f2390040. (CVE-2020-12770)

  - u'Specifically timed and handcrafted traffic can cause internal errors in a WLAN device that lead to
    improper layer 2 Wi-Fi encryption with a consequent possibility of information disclosure over the air for
    a discrete set of traffic' in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon
    Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon
    Wearables, Snapdragon Wired Infrastructure and Networking in APQ8053, IPQ4019, IPQ8064, MSM8909W,
    MSM8996AU, QCA9531, QCN5502, QCS405, SDX20, SM6150, SM7150 (CVE-2020-3702)

  - In bpf_skb_change_head of filter.c, there is a possible out of bounds read due to a use after free. This
    could lead to local escalation of privilege with System execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-154177719References:
    Upstream kernel (CVE-2021-0941)

  - An issue was discovered in Linux: KVM through Improper handling of VM_IO|VM_PFNMAP vmas in KVM can bypass
    RO checks and can lead to pages being freed while still accessible by the VMM and guest. This allows users
    with the ability to start and control a VM to read/write random pages of memory and can result in local
    privilege escalation. (CVE-2021-22543)

  - An out-of-bounds (OOB) memory write flaw was found in list_devices in drivers/md/dm-ioctl.c in the Multi-
    device driver module in the Linux kernel before 5.12. A bound check failure allows an attacker with
    special user (CAP_SYS_ADMIN) privilege to gain access to out-of-bounds memory leading to a system crash or
    a leak of internal kernel information. The highest threat from this vulnerability is to system
    availability. (CVE-2021-31916)

  - In the Linux kernel through 5.13.7, an unprivileged BPF program can obtain sensitive information from
    kernel memory via a Speculative Store Bypass side-channel attack because the protection mechanism neglects
    the possibility of uninitialized memory locations on the BPF stack. (CVE-2021-34556)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2021-42739. Reason: This candidate is a
    reservation duplicate of CVE-2021-42739. Notes: All CVE users should reference CVE-2021-42739 instead of
    this candidate. All references and descriptions in this candidate have been removed to prevent accidental
    usage. (CVE-2021-3542)

  - In the Linux kernel through 5.13.7, an unprivileged BPF program can obtain sensitive information from
    kernel memory via a Speculative Store Bypass side-channel attack because a certain preempting store
    operation does not necessarily occur before a store operation that has an attacker-controlled value.
    (CVE-2021-35477)

  - A flaw was found in the KVM's AMD code for supporting SVM nested virtualization. The flaw occurs when
    processing the VMCB (virtual machine control block) provided by the L1 guest to spawn/handle a nested
    guest (L2). Due to improper validation of the int_ctl field, this issue could allow a malicious L1 to
    enable AVIC support (Advanced Virtual Interrupt Controller) for the L2 guest. As a result, the L2 guest
    would be allowed to read/write physical pages of the host, resulting in a crash of the entire system, leak
    of sensitive data or potential guest-to-host escape. This flaw affects Linux kernel versions prior to
    5.14-rc7. (CVE-2021-3653)

  - A vulnerability was found in the Linux kernel in versions prior to v5.14-rc1. Missing size validations on
    inbound SCTP packets may allow the kernel to read uninitialized memory. (CVE-2021-3655)

  - kernel: SVM nested virtualization issue in KVM (VMLOAD/VMSAVE) (CVE-2021-3656)

  - kernel: NULL pointer dereference in llsec_key_alloc() in net/mac802154/llsec.c (CVE-2021-3659)

  - A lack of CPU resource in the Linux kernel tracing module functionality in versions prior to 5.14-rc3 was
    found in the way user uses trace ring buffer in a specific way. Only privileged local users (with
    CAP_SYS_ADMIN capability) could use this flaw to starve the resources causing denial of service.
    (CVE-2021-3679)

  - kernel: use-after-free in route4_change() in net/sched/cls_route.c (CVE-2021-3715)

  - hso_free_net_device in drivers/net/usb/hso.c in the Linux kernel through 5.13.4 calls unregister_netdev
    without checking for the NETREG_REGISTERED state, leading to a use-after-free and a double free.
    (CVE-2021-37159)

  - kernel: overlayfs: Mounting overlayfs inside an unprivileged user namespace can reveal files
    (CVE-2021-3732)

  - ccp - fix resource leaks in ccp_run_aes_gcm_cmd() [fedora-all] (CVE-2021-3744)

  - A flaw was found in the Linux kernel. When reusing a socket with an attached dccps_hc_tx_ccid as a
    listener, the socket will be used after being released leading to denial of service (DoS) or a potential
    code execution. The highest threat from this vulnerability is to data confidentiality and integrity as
    well as system availability. (CVE-2020-16119) (CVE-2021-3753)

  - arch/powerpc/kvm/book3s_rtas.c in the Linux kernel through 5.13.5 on the powerpc platform allows KVM guest
    OS users to cause host OS memory corruption via rtas_args.nargs, aka CID-f62f3c20647e. (CVE-2021-37576)

  - A flaw was found in the Linux kernel. A corrupted timer tree caused the task wakeup to be missing in the
    timerqueue_add function in lib/timerqueue.c. This flaw allows a local attacker with special user
    privileges to cause a denial of service, slowing and eventually stopping the system while running OSP. The
    highest threat from this vulnerability is system availability. (CVE-2021-20317) (CVE-2021-3764)

  - ** DISPUTED ** In drivers/char/virtio_console.c in the Linux kernel before 5.13.4, data corruption or loss
    can be triggered by an untrusted device that supplies a buf->len value exceeding the buffer size. NOTE:
    the vendor indicates that the cited data corruption is not a vulnerability in any existing use case; the
    length validation was added solely for robustness in the face of anomalous host OS behavior.
    (CVE-2021-38160)

  - arch/x86/kvm/mmu/paging_tmpl.h in the Linux kernel before 5.12.11 incorrectly computes the access
    permissions of a shadow page, leading to a missing guest protection page fault. (CVE-2021-38198)

  - drivers/usb/host/max3421-hcd.c in the Linux kernel before 5.13.6 allows physically proximate attackers to
    cause a denial of service (use-after-free and panic) by removing a MAX-3421 USB device in certain
    situations. (CVE-2021-38204)

  - A race condition was discovered in ext4_write_inline_data_end in fs/ext4/inline.c in the ext4 subsystem in
    the Linux kernel through 5.13.13. (CVE-2021-40490)

  - prealloc_elems_and_freelist in kernel/bpf/stackmap.c in the Linux kernel through 5.14.9 allows
    unprivileged users to trigger an eBPF multiplication integer overflow with a resultant out-of-bounds
    write. (CVE-2021-41864)

  - The decode_data function in drivers/net/hamradio/6pack.c in the Linux kernel before 5.13.13 has a slab
    out-of-bounds write. Input from a process that has the CAP_NET_ADMIN capability can lead to root access.
    (CVE-2021-42008)

  - An issue was discovered in aspeed_lpc_ctrl_mmap in drivers/soc/aspeed/aspeed-lpc-ctrl.c in the Linux
    kernel before 5.14.6. Local attackers able to access the Aspeed LPC control interface could overwrite
    memory in the kernel and potentially execute privileges, aka CID-b49a0e69a7b1. This occurs because a
    certain comparison uses values that are not memory sizes. (CVE-2021-42252)

  - The firewire subsystem in the Linux kernel through 5.14.13 has a buffer overflow related to
    drivers/media/firewire/firedtv-avc.c and drivers/media/firewire/firedtv-ci.c, because avc_ca_pmt
    mishandles bounds checking. (CVE-2021-42739)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1087082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1100416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1108488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1129735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1129898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1133374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1153720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190159");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190276");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190351");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192802");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-December/009872.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d4473a3");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-13405");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-9517");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-0429");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12770");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3702");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20322");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22543");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-31916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-34556");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-34981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3542");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-35477");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3655");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37159");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3732");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3752");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37576");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3760");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3764");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38198");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38204");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-40490");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42252");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42739");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3752");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3656");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-95_83-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3/4/5", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'kernel-default-4.12.14-95.83.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'kernel-default-base-4.12.14-95.83.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'kernel-default-devel-4.12.14-95.83.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'kernel-devel-4.12.14-95.83.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'kernel-macros-4.12.14-95.83.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'kernel-source-4.12.14-95.83.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'kernel-syms-4.12.14-95.83.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'cluster-md-kmp-default-4.12.14-95.83.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-12.4'},
    {'reference':'cluster-md-kmp-default-4.12.14-95.83.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-12.4'},
    {'reference':'cluster-md-kmp-default-4.12.14-95.83.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-12.4'},
    {'reference':'dlm-kmp-default-4.12.14-95.83.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-12.4'},
    {'reference':'dlm-kmp-default-4.12.14-95.83.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-12.4'},
    {'reference':'dlm-kmp-default-4.12.14-95.83.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-12.4'},
    {'reference':'gfs2-kmp-default-4.12.14-95.83.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-12.4'},
    {'reference':'gfs2-kmp-default-4.12.14-95.83.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-12.4'},
    {'reference':'gfs2-kmp-default-4.12.14-95.83.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-12.4'},
    {'reference':'ocfs2-kmp-default-4.12.14-95.83.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-12.4'},
    {'reference':'ocfs2-kmp-default-4.12.14-95.83.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-12.4'},
    {'reference':'ocfs2-kmp-default-4.12.14-95.83.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-12.4'},
    {'reference':'kernel-default-kgraft-4.12.14-95.83.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-live-patching-release-12.4'},
    {'reference':'kernel-default-kgraft-devel-4.12.14-95.83.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-live-patching-release-12.4'},
    {'reference':'kgraft-patch-4_12_14-95_83-default-1-6.3.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-live-patching-release-12.4'},
    {'reference':'kernel-default-4.12.14-95.83.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'kernel-default-base-4.12.14-95.83.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'kernel-default-devel-4.12.14-95.83.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'kernel-default-man-4.12.14-95.83.2', 'sp':'4', 'cpu':'s390x', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'kernel-devel-4.12.14-95.83.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'kernel-macros-4.12.14-95.83.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'kernel-source-4.12.14-95.83.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'kernel-syms-4.12.14-95.83.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
