#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:4574-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(168941);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2021-4037",
    "CVE-2022-2153",
    "CVE-2022-2964",
    "CVE-2022-3169",
    "CVE-2022-3424",
    "CVE-2022-3521",
    "CVE-2022-3524",
    "CVE-2022-3542",
    "CVE-2022-3545",
    "CVE-2022-3565",
    "CVE-2022-3567",
    "CVE-2022-3586",
    "CVE-2022-3594",
    "CVE-2022-3621",
    "CVE-2022-3628",
    "CVE-2022-3629",
    "CVE-2022-3635",
    "CVE-2022-3643",
    "CVE-2022-3646",
    "CVE-2022-3649",
    "CVE-2022-3903",
    "CVE-2022-4095",
    "CVE-2022-4378",
    "CVE-2022-28693",
    "CVE-2022-40307",
    "CVE-2022-40768",
    "CVE-2022-41850",
    "CVE-2022-41858",
    "CVE-2022-42328",
    "CVE-2022-42329",
    "CVE-2022-42703",
    "CVE-2022-42895",
    "CVE-2022-42896",
    "CVE-2022-43750",
    "CVE-2022-43945",
    "CVE-2022-45934"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:4574-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2022:4574-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2022:4574-1 advisory.

  - A vulnerability was found in the fs/inode.c:inode_init_owner() function logic of the LInux kernel that
    allows local users to create files for the XFS file-system with an unintended group ownership and with
    group execution and SGID permission bits set, in a scenario where a directory is SGID and belongs to a
    certain group and is writable by a user who is not a member of this group. This can lead to excessive
    permissions granted in case when they should not. This vulnerability is similar to the previous
    CVE-2018-13405 and adds the missed fix for the XFS. (CVE-2021-4037)

  - A flaw was found in the Linux kernel's KVM when attempting to set a SynIC IRQ. This issue makes it
    possible for a misbehaving VMM to write to SYNIC/STIMER MSRs, causing a NULL pointer dereference. This
    flaw allows an unprivileged local attacker on the host to issue specific ioctl calls, causing a kernel
    oops condition that results in a denial of service. (CVE-2022-2153)

  - A flaw was found in hw. Mis-trained branch predictions for return instructions may allow arbitrary
    speculative code execution under certain microarchitecture-dependent conditions. (CVE-2022-23816)
    (CVE-2022-28693)

  - A flaw was found in the Linux kernel's driver for the ASIX AX88179_178A-based USB 2.0/3.0 Gigabit Ethernet
    Devices. The vulnerability contains multiple out-of-bounds reads and possible out-of-bounds writes.
    (CVE-2022-2964)

  - A flaw was found in the Linux kernel. A denial of service flaw may occur if there is a consecutive request
    of the NVME_IOCTL_RESET and the NVME_IOCTL_SUBSYS_RESET through the device file of the driver, resulting
    in a PCIe link disconnect. (CVE-2022-3169)

  - A use-after-free flaw was found in the Linux kernel's SGI GRU driver in the way the first
    gru_file_unlocked_ioctl function is called by the user, where a fail pass occurs in the
    gru_check_chiplet_assignment function. This flaw allows a local user to crash or potentially escalate
    their privileges on the system. (CVE-2022-3424)

  - A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects
    the function kcm_tx_work of the file net/kcm/kcmsock.c of the component kcm. The manipulation leads to
    race condition. It is recommended to apply a patch to fix this issue. VDB-211018 is the identifier
    assigned to this vulnerability. (CVE-2022-3521)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function ipv6_renew_options of the component IPv6 Handler. The manipulation leads to
    memory leak. The attack can be launched remotely. It is recommended to apply a patch to fix this issue.
    The identifier VDB-211021 was assigned to this vulnerability. (CVE-2022-3524)

  - A vulnerability has been found in Linux Kernel and classified as critical. Affected by this vulnerability
    is the function area_cache_get of the file drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c of the
    component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this
    issue. The identifier VDB-211045 was assigned to this vulnerability. (CVE-2022-3545)

  - A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue
    is the function del_timer of the file drivers/isdn/mISDN/l1oip_core.c of the component Bluetooth. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    of this vulnerability is VDB-211088. (CVE-2022-3565)

  - A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects
    the function inet6_stream_ops/inet6_dgram_ops of the component IPv6 Handler. The manipulation leads to
    race condition. It is recommended to apply a patch to fix this issue. VDB-211090 is the identifier
    assigned to this vulnerability. (CVE-2022-3567)

  - A flaw was found in the Linux kernel's networking code. A use-after-free was found in the way the sch_sfb
    enqueue function used the socket buffer (SKB) cb field after the same SKB had been enqueued (and freed)
    into a child qdisc. This flaw allows a local, unprivileged user to crash the system, causing a denial of
    service. (CVE-2022-3586)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function intr_callback of the file drivers/net/usb/r8152.c of the component BPF. The
    manipulation leads to logging of excessive data. The attack can be launched remotely. It is recommended to
    apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211363.
    (CVE-2022-3594)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is the function
    nilfs_bmap_lookup_at_level of the file fs/nilfs2/inode.c of the component nilfs2. The manipulation leads
    to null pointer dereference. It is possible to launch the attack remotely. It is recommended to apply a
    patch to fix this issue. The identifier of this vulnerability is VDB-211920. (CVE-2022-3621)

  - A buffer overflow flaw was found in the Linux kernel Broadcom Full MAC Wi-Fi driver. This issue occurs
    when a user connects to a malicious USB device. This can allow a local user to crash the system or
    escalate their privileges. (CVE-2022-3628)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. This vulnerability affects
    the function vsock_connect of the file net/vmw_vsock/af_vsock.c. The manipulation leads to memory leak. It
    is recommended to apply a patch to fix this issue. VDB-211930 is the identifier assigned to this
    vulnerability. (CVE-2022-3629)

  - A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue
    is the function tst_timer of the file drivers/atm/idt77252.c of the component IPsec. The manipulation
    leads to use after free. It is recommended to apply a patch to fix this issue. VDB-211934 is the
    identifier assigned to this vulnerability. (CVE-2022-3635)

  - Guests can trigger NIC interface reset/abort/crash via netback It is possible for a guest to trigger a NIC
    interface reset/abort/crash in a Linux based network backend by sending certain kinds of packets. It
    appears to be an (unwritten?) assumption in the rest of the Linux network stack that packet protocol
    headers are all contained within the linear section of the SKB and some NICs behave badly if this is not
    the case. This has been reported to occur with Cisco (enic) and Broadcom NetXtrem II BCM5780 (bnx2x)
    though it may be an issue with other NICs/drivers as well. In case the frontend is sending requests with
    split headers, netback will forward those violating above mentioned assumption to the networking core,
    resulting in said misbehavior. (CVE-2022-3643)

  - A vulnerability, which was classified as problematic, has been found in Linux Kernel. This issue affects
    the function nilfs_attach_log_writer of the file fs/nilfs2/segment.c of the component BPF. The
    manipulation leads to memory leak. The attack may be initiated remotely. It is recommended to apply a
    patch to fix this issue. The identifier VDB-211961 was assigned to this vulnerability. (CVE-2022-3646)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is the function
    nilfs_new_inode of the file fs/nilfs2/inode.c of the component BPF. The manipulation leads to use after
    free. It is possible to launch the attack remotely. It is recommended to apply a patch to fix this issue.
    The identifier of this vulnerability is VDB-211992. (CVE-2022-3649)

  - An incorrect read request flaw was found in the Infrared Transceiver USB driver in the Linux kernel. This
    issue occurs when a user attaches a malicious USB device. A local user could use this flaw to starve the
    resources, causing denial of service or potentially crashing the system. (CVE-2022-3903)

  - An issue was discovered in the Linux kernel through 5.19.8. drivers/firmware/efi/capsule-loader.c has a
    race condition with a resultant use-after-free. (CVE-2022-40307)

  - drivers/scsi/stex.c in the Linux kernel through 5.19.9 allows local users to obtain sensitive information
    from kernel memory because stex_queuecommand_lck lacks a memset for the PASSTHRU_CMD case.
    (CVE-2022-40768)

  - roccat_report_event in drivers/hid/hid-roccat.c in the Linux kernel through 5.19.12 has a race condition
    and resultant use-after-free in certain situations where a report is received while copying a
    report->value is in progress. (CVE-2022-41850)

  - A flaw was found in the Linux kernel. A NULL pointer dereference may occur while a slip driver is in
    progress to detach in sl_tx_timeout in drivers/net/slip/slip.c. This issue could allow an attacker to
    crash the system or leak internal kernel information. (CVE-2022-41858)

  - Guests can trigger deadlock in Linux netback driver T[his CNA information record relates to multiple CVEs;
    the text explains which aspects/vulnerabilities correspond to which CVE.] The patch for XSA-392 introduced
    another issue which might result in a deadlock when trying to free the SKB of a packet dropped due to the
    XSA-392 handling (CVE-2022-42328). Additionally when dropping packages for other reasons the same deadlock
    could occur in case of netpoll being active for the interface the xen-netback driver is connected to
    (CVE-2022-42329). (CVE-2022-42328, CVE-2022-42329)

  - mm/rmap.c in the Linux kernel before 5.19.7 has a use-after-free related to leaf anon_vma double reuse.
    (CVE-2022-42703)

  - There is an infoleak vulnerability in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_parse_conf_req
    function which can be used to leak kernel pointers remotely. We recommend upgrading past commit
    https://github.com/torvalds/linux/commit/b1a2cd50c0357f243b7435a732b4e62ba3157a2e
    https://www.google.com/url (CVE-2022-42895)

  - There are use-after-free vulnerabilities in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_connect
    and l2cap_le_connect_req functions which may allow code execution and leaking kernel memory (respectively)
    remotely via Bluetooth. A remote attacker could execute code leaking kernel memory via Bluetooth if within
    proximity of the victim. We recommend upgrading past commit https://www.google.com/url
    https://github.com/torvalds/linux/commit/711f8c3fb3db61897080468586b970c87c61d9e4
    https://www.google.com/url (CVE-2022-42896)

  - drivers/usb/mon/mon_bin.c in usbmon in the Linux kernel before 5.19.15 and 6.x before 6.0.1 allows a user-
    space client to corrupt the monitor's internal memory. (CVE-2022-43750)

  - A stack overflow flaw was found in the Linux kernel's SYSCTL subsystem in how a user changes certain
    kernel parameters and variables. This flaw allows a local user to crash or potentially escalate their
    privileges on the system. (CVE-2022-4378)

  - The Linux kernel NFSD implementation prior to versions 5.19.17 and 6.0.2 are vulnerable to buffer
    overflow. NFSD tracks the number of pages held by each NFSD thread by combining the receive and send
    buffers of a remote procedure call (RPC) into a single array of pages. A client can force the send buffer
    to shrink by sending an RPC message over TCP with garbage data added at the end of the message. The RPC
    message with garbage data is still correctly formed according to the specification and is passed forward
    to handlers. Vulnerable code in NFSD is not expecting the oversized request and writes beyond the
    allocated buffer space. CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H (CVE-2022-43945)

  - An issue was discovered in the Linux kernel through 6.0.10. l2cap_config_req in net/bluetooth/l2cap_core.c
    has an integer wraparound via L2CAP_CONF_REQ packets. (CVE-2022-45934)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204402");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206207");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-December/013279.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffbb11d6");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4037");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2153");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3169");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3424");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3521");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3524");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3542");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3565");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3586");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3621");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3629");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3643");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3649");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40307");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40768");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42328");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42329");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-43750");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4378");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-43945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45934");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3649");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3643");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150100_197_131-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.3|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-default-base-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-default-devel-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-devel-4.12.14-150100.197.131.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-macros-4.12.14-150100.197.131.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-obs-build-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-source-4.12.14-150100.197.131.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-syms-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'reiserfs-kmp-default-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1']},
    {'reference':'kernel-default-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-default-base-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-default-devel-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-obs-build-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-syms-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-default-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-default-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-default-base-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-default-base-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-default-devel-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-default-devel-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-devel-4.12.14-150100.197.131.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'kernel-macros-4.12.14-150100.197.131.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'kernel-obs-build-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-obs-build-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-source-4.12.14-150100.197.131.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'kernel-syms-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-syms-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-debug-base-4.12.14-150100.197.131.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-default-man-4.12.14-150100.197.131.1', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-kvmsmall-base-4.12.14-150100.197.131.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-vanilla-4.12.14-150100.197.131.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-vanilla-base-4.12.14-150100.197.131.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-vanilla-devel-4.12.14-150100.197.131.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-vanilla-livepatch-devel-4.12.14-150100.197.131.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-zfcpdump-man-4.12.14-150100.197.131.1', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-debug-base-4.12.14-150100.197.131.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-default-man-4.12.14-150100.197.131.1', 'cpu':'s390x', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-kvmsmall-base-4.12.14-150100.197.131.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-vanilla-4.12.14-150100.197.131.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-vanilla-base-4.12.14-150100.197.131.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-vanilla-devel-4.12.14-150100.197.131.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-vanilla-livepatch-devel-4.12.14-150100.197.131.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-zfcpdump-man-4.12.14-150100.197.131.1', 'cpu':'s390x', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'cluster-md-kmp-default-4.12.14-150100.197.131.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'dlm-kmp-default-4.12.14-150100.197.131.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'gfs2-kmp-default-4.12.14-150100.197.131.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'ocfs2-kmp-default-4.12.14-150100.197.131.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'kernel-default-livepatch-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']},
    {'reference':'kernel-default-livepatch-devel-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']},
    {'reference':'kernel-livepatch-4_12_14-150100_197_131-default-1-150100.3.5.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']},
    {'reference':'kernel-default-4.12.14-150100.197.131.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'kernel-default-base-4.12.14-150100.197.131.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'kernel-default-devel-4.12.14-150100.197.131.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'kernel-default-man-4.12.14-150100.197.131.1', 'sp':'1', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'kernel-obs-build-4.12.14-150100.197.131.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'kernel-syms-4.12.14-150100.197.131.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'reiserfs-kmp-default-4.12.14-150100.197.131.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
