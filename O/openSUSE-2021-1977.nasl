#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1977-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151756);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2019-18814",
    "CVE-2019-19769",
    "CVE-2020-24586",
    "CVE-2020-24587",
    "CVE-2020-24588",
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-25672",
    "CVE-2020-25673",
    "CVE-2020-26139",
    "CVE-2020-26141",
    "CVE-2020-26145",
    "CVE-2020-26147",
    "CVE-2020-27170",
    "CVE-2020-27171",
    "CVE-2020-27673",
    "CVE-2020-27815",
    "CVE-2020-35519",
    "CVE-2020-36310",
    "CVE-2020-36311",
    "CVE-2020-36312",
    "CVE-2020-36322",
    "CVE-2021-3428",
    "CVE-2021-3444",
    "CVE-2021-3483",
    "CVE-2021-3489",
    "CVE-2021-3490",
    "CVE-2021-3491",
    "CVE-2021-20268",
    "CVE-2021-23134",
    "CVE-2021-27363",
    "CVE-2021-27364",
    "CVE-2021-27365",
    "CVE-2021-28038",
    "CVE-2021-28375",
    "CVE-2021-28660",
    "CVE-2021-28688",
    "CVE-2021-28950",
    "CVE-2021-28952",
    "CVE-2021-28964",
    "CVE-2021-28971",
    "CVE-2021-28972",
    "CVE-2021-29154",
    "CVE-2021-29155",
    "CVE-2021-29264",
    "CVE-2021-29265",
    "CVE-2021-29647",
    "CVE-2021-29650",
    "CVE-2021-30002",
    "CVE-2021-32399",
    "CVE-2021-33034",
    "CVE-2021-33200"
  );

  script_name(english:"openSUSE 15 Security Update : kernel (openSUSE-SU-2021:1977-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1977-1 advisory.

  - An issue was discovered in the Linux kernel through 5.3.9. There is a use-after-free when aa_label_parse()
    fails in aa_audit_rule_init() in security/apparmor/audit.c. (CVE-2019-18814)

  - In the Linux kernel 5.3.10, there is a use-after-free (read) in the perf_trace_lock_acquire function
    (related to include/trace/events/lock.h). (CVE-2019-19769)

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that received fragments be cleared from memory after (re)connecting to a
    network. Under the right circumstances, when another device sends fragmented frames encrypted using WEP,
    CCMP, or GCMP, this can be abused to inject arbitrary network packets and/or exfiltrate user data.
    (CVE-2020-24586)

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that all fragments of a frame are encrypted under the same key. An adversary
    can abuse this to decrypt selected fragments when another device sends fragmented frames and the WEP,
    CCMP, or GCMP encryption key is periodically renewed. (CVE-2020-24587)

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that the A-MSDU flag in the plaintext QoS header field is authenticated.
    Against devices that support receiving non-SSP A-MSDU frames (which is mandatory as part of 802.11n), an
    adversary can abuse this to inject arbitrary network packets. (CVE-2020-24588)

  - A vulnerability was found in Linux Kernel where refcount leak in llcp_sock_bind() causing use-after-free
    which might lead to privilege escalations. (CVE-2020-25670)

  - A vulnerability was found in Linux Kernel, where a refcount leak in llcp_sock_connect() causing use-after-
    free which might lead to privilege escalations. (CVE-2020-25671)

  - A memory leak vulnerability was found in Linux kernel in llcp_sock_connect (CVE-2020-25672)

  - A vulnerability was found in Linux kernel where non-blocking socket in llcp_sock_connect() leads to leak
    and eventually hanging-up the system. (CVE-2020-25673)

  - An issue was discovered in the kernel in NetBSD 7.1. An Access Point (AP) forwards EAPOL frames to other
    clients even though the sender has not yet successfully authenticated to the AP. This might be abused in
    projected Wi-Fi networks to launch denial-of-service attacks against connected clients and makes it easier
    to exploit other vulnerabilities in connected clients. (CVE-2020-26139)

  - An issue was discovered in the ALFA Windows 10 driver 6.1316.1209 for AWUS036H. The Wi-Fi implementation
    does not verify the Message Integrity Check (authenticity) of fragmented TKIP frames. An adversary can
    abuse this to inject and possibly decrypt packets in WPA or WPA2 networks that support the TKIP data-
    confidentiality protocol. (CVE-2020-26141)

  - An issue was discovered on Samsung Galaxy S3 i9305 4.4.4 devices. The WEP, WPA, WPA2, and WPA3
    implementations accept second (or subsequent) broadcast fragments even when sent in plaintext and process
    them as full unfragmented frames. An adversary can abuse this to inject arbitrary network packets
    independent of the network configuration. (CVE-2020-26145)

  - An issue was discovered in the Linux kernel 5.8.9. The WEP, WPA, WPA2, and WPA3 implementations reassemble
    fragments even though some of them were sent in plaintext. This vulnerability can be abused to inject
    packets and/or exfiltrate selected fragments when another device sends fragmented frames and the WEP,
    CCMP, or GCMP data-confidentiality protocol is used. (CVE-2020-26147)

  - An issue was discovered in the Linux kernel before 5.11.8. kernel/bpf/verifier.c performs undesirable out-
    of-bounds speculation on pointer arithmetic, leading to side-channel attacks that defeat Spectre
    mitigations and obtain sensitive information from kernel memory, aka CID-f232326f6966. This affects
    pointer types that do not define a ptr_limit. (CVE-2020-27170)

  - An issue was discovered in the Linux kernel before 5.11.8. kernel/bpf/verifier.c has an off-by-one error
    (with a resultant integer underflow) affecting out-of-bounds speculation on pointer arithmetic, leading to
    side-channel attacks that defeat Spectre mitigations and obtain sensitive information from kernel memory,
    aka CID-10d2bb2e6b1d. (CVE-2020-27171)

  - An issue was discovered in the Linux kernel through 5.9.1, as used with Xen through 4.14.x. Guest OS users
    can cause a denial of service (host OS hang) via a high rate of events to dom0, aka CID-e99502f76271.
    (CVE-2020-27673)

  - A flaw was found in the JFS filesystem code in the Linux Kernel which allows a local attacker with the
    ability to set extended attributes to panic the system, causing memory corruption or escalating
    privileges. The highest threat from this vulnerability is to confidentiality, integrity, as well as system
    availability. (CVE-2020-27815)

  - An out-of-bounds (OOB) memory access flaw was found in x25_bind in net/x25/af_x25.c in the Linux kernel
    version v5.12-rc5. A bounds check failure allows a local attacker with a user account on the system to
    gain access to out-of-bounds memory, leading to a system crash or a leak of internal kernel information.
    The highest threat from this vulnerability is to confidentiality, integrity, as well as system
    availability. (CVE-2020-35519)

  - An issue was discovered in the Linux kernel before 5.8. arch/x86/kvm/svm/svm.c allows a
    set_memory_region_test infinite loop for certain nested page faults, aka CID-e72436bc3a52.
    (CVE-2020-36310)

  - An issue was discovered in the Linux kernel before 5.9. arch/x86/kvm/svm/sev.c allows attackers to cause a
    denial of service (soft lockup) by triggering destruction of a large SEV VM (which requires unregistering
    many encrypted regions), aka CID-7be74942f184. (CVE-2020-36311)

  - An issue was discovered in the Linux kernel before 5.8.10. virt/kvm/kvm_main.c has a
    kvm_io_bus_unregister_dev memory leak upon a kmalloc failure, aka CID-f65886606c2d. (CVE-2020-36312)

  - An issue was discovered in the FUSE filesystem implementation in the Linux kernel before 5.10.6, aka
    CID-5d069dbe8aaf. fuse_do_getattr() calls make_bad_inode() in inappropriate situations, causing a system
    crash. NOTE: the original fix for this vulnerability was incomplete, and its incompleteness is tracked as
    CVE-2021-28950. (CVE-2020-36322)

  - An out-of-bounds access flaw was found in the Linux kernel's implementation of the eBPF code verifier in
    the way a user running the eBPF script calls dev_map_init_map or sock_map_alloc. This flaw allows a local
    user to crash the system or possibly escalate their privileges. The highest threat from this vulnerability
    is to confidentiality, integrity, as well as system availability. (CVE-2021-20268)

  - Use After Free vulnerability in nfc sockets in the Linux Kernel before 5.12.4 allows local attackers to
    elevate their privileges. In typical configurations, the issue can only be triggered by a privileged local
    user with the CAP_NET_RAW capability. (CVE-2021-23134)

  - An issue was discovered in the Linux kernel through 5.11.3. A kernel pointer leak can be used to determine
    the address of the iscsi_transport structure. When an iSCSI transport is registered with the iSCSI
    subsystem, the transport's handle is available to unprivileged users via the sysfs file system, at
    /sys/class/iscsi_transport/$TRANSPORT_NAME/handle. When read, the show_transport_handle function (in
    drivers/scsi/scsi_transport_iscsi.c) is called, which leaks the handle. This handle is actually the
    pointer to an iscsi_transport struct in the kernel module's global variables. (CVE-2021-27363)

  - An issue was discovered in the Linux kernel through 5.11.3. drivers/scsi/scsi_transport_iscsi.c is
    adversely affected by the ability of an unprivileged user to craft Netlink messages. (CVE-2021-27364)

  - An issue was discovered in the Linux kernel through 5.11.3. Certain iSCSI data structures do not have
    appropriate length constraints or checks, and can exceed the PAGE_SIZE value. An unprivileged user can
    send a Netlink message that is associated with iSCSI, and has a length up to the maximum length of a
    Netlink message. (CVE-2021-27365)

  - An issue was discovered in the Linux kernel through 5.11.3, as used with Xen PV. A certain part of the
    netback driver lacks necessary treatment of errors such as failed memory allocations (as a result of
    changes to the handling of grant mapping errors). A host OS denial of service may occur during misbehavior
    of a networking frontend driver. NOTE: this issue exists because of an incomplete fix for CVE-2021-26931.
    (CVE-2021-28038)

  - An issue was discovered in the Linux kernel through 5.11.6. fastrpc_internal_invoke in
    drivers/misc/fastrpc.c does not prevent user applications from sending kernel RPC messages, aka
    CID-20c40794eb85. This is a related issue to CVE-2019-2308. (CVE-2021-28375)

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

  - BPF JIT compilers in the Linux kernel through 5.11.12 have incorrect computation of branch displacements,
    allowing them to execute arbitrary code within the kernel context. This affects
    arch/x86/net/bpf_jit_comp.c and arch/x86/net/bpf_jit_comp32.c. (CVE-2021-29154)

  - An issue was discovered in the Linux kernel through 5.11.x. kernel/bpf/verifier.c performs undesirable
    out-of-bounds speculation on pointer arithmetic, leading to side-channel attacks that defeat Spectre
    mitigations and obtain sensitive information from kernel memory. Specifically, for sequences of pointer
    arithmetic operations, the pointer modification performed by the first operation is not correctly
    accounted for when restricting subsequent operations. (CVE-2021-29155)

  - An issue was discovered in the Linux kernel through 5.11.10. drivers/net/ethernet/freescale/gianfar.c in
    the Freescale Gianfar Ethernet driver allows attackers to cause a system crash because a negative fragment
    size is calculated in situations involving an rx queue overrun when jumbo packets are used and NAPI is
    enabled, aka CID-d8861bab48b6. (CVE-2021-29264)

  - An issue was discovered in the Linux kernel before 5.11.7. usbip_sockfd_store in
    drivers/usb/usbip/stub_dev.c allows attackers to cause a denial of service (GPF) because the stub-up
    sequence has race conditions during an update of the local and shared status, aka CID-9380afd6df70.
    (CVE-2021-29265)

  - An issue was discovered in the Linux kernel before 5.11.11. qrtr_recvmsg in net/qrtr/qrtr.c allows
    attackers to obtain sensitive information from kernel memory because of a partially uninitialized data
    structure, aka CID-50535249f624. (CVE-2021-29647)

  - An issue was discovered in the Linux kernel before 5.11.11. The netfilter subsystem allows attackers to
    cause a denial of service (panic) because net/netfilter/x_tables.c and include/linux/netfilter/x_tables.h
    lack a full memory barrier upon the assignment of a new table value, aka CID-175e476b8cdf.
    (CVE-2021-29650)

  - An issue was discovered in the Linux kernel before 5.11.3 when a webcam device exists. video_usercopy in
    drivers/media/v4l2-core/v4l2-ioctl.c has a memory leak for large arguments, aka CID-fb18802a338b.
    (CVE-2021-30002)

  - net/bluetooth/hci_request.c in the Linux kernel through 5.12.2 has a race condition for removal of the HCI
    controller. (CVE-2021-32399)

  - In the Linux kernel before 5.12.4, net/bluetooth/hci_event.c has a use-after-free when destroying an
    hci_chan, aka CID-5c4c8c954409. This leads to writing an arbitrary value. (CVE-2021-33034)

  - kernel/bpf/verifier.c in the Linux kernel through 5.12.7 enforces incorrect limits for pointer arithmetic
    operations, aka CID-bb01a1bba579. This can be abused to perform out-of-bounds reads and writes in kernel
    memory, leading to local privilege escalation to root. In particular, there is a corner case where the off
    reg causes a masking direction change, which then results in an incorrect final aux->alu_limit.
    (CVE-2021-33200)

  - The bpf verifier in the Linux kernel did not properly handle mod32 destination register truncation when
    the source register was known to be 0. A local attacker with the ability to load bpf programs could use
    this gain out-of-bounds reads in kernel memory leading to information disclosure (kernel memory), and
    possibly out-of-bounds writes that could potentially lead to code execution. This issue was addressed in
    the upstream kernel in commit 9b00f1b78809 (bpf: Fix truncation handling for mod32 dst reg wrt zero) and
    in Linux stable kernels 5.11.2, 5.10.19, and 5.4.101. (CVE-2021-3444)

  - A flaw was found in the Nosy driver in the Linux kernel. This issue allows a device to be inserted twice
    into a doubly-linked list, leading to a use-after-free when one of these devices is removed. The highest
    threat from this vulnerability is to confidentiality, integrity, as well as system availability. Versions
    before kernel 5.12-rc6 are affected (CVE-2021-3483)

  - The eBPF RINGBUF bpf_ringbuf_reserve() function in the Linux kernel did not check that the allocated size
    was smaller than the ringbuf size, allowing an attacker to perform out-of-bounds writes within the kernel
    and therefore, arbitrary code execution. This issue was fixed via commit 4b81ccebaeee (bpf, ringbuf: Deny
    reserve of buffers larger than ringbuf) (v5.13-rc4) and backported to the stable kernels in v5.12.4,
    v5.11.21, and v5.10.37. It was introduced via 457f44363a88 (bpf: Implement BPF ring buffer and verifier
    support for it) (v5.8-rc1). (CVE-2021-3489)

  - The eBPF ALU32 bounds tracking for bitwise ops (AND, OR and XOR) in the Linux kernel did not properly
    update 32-bit bounds, which could be turned into out of bounds reads and writes in the Linux kernel and
    therefore, arbitrary code execution. This issue was fixed via commit 049c4e13714e (bpf: Fix alu32 const
    subreg bound tracking on bitwise operations) (v5.13-rc4) and backported to the stable kernels in v5.12.4,
    v5.11.21, and v5.10.37. The AND/OR issues were introduced by commit 3f50f132d840 (bpf: Verifier, do
    explicit ALU32 bounds tracking) (5.7-rc1) and the XOR variant was introduced by 2921c90d4718 (bpf:Fix a
    verifier failure with xor) ( 5.10-rc1). (CVE-2021-3490)

  - The io_uring subsystem in the Linux kernel allowed the MAX_RW_COUNT limit to be bypassed in the
    PROVIDE_BUFFERS operation, which led to negative values being usedin mem_rw when reading /proc//mem.
    This could be used to create a heap overflow leading to arbitrary code execution in the kernel. It was
    addressed via commit d1f82808877b (io_uring: truncate lengths larger than MAX_RW_COUNT on provide
    buffers) (v5.13-rc1) and backported to the stable kernels in v5.12.4, v5.11.21, and v5.10.37. It was
    introduced in ddf0322db79c (io_uring: add IORING_OP_PROVIDE_BUFFERS) (v5.7-rc1). (CVE-2021-3491)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1055117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1087082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1113295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1133021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1153274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1155518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1168777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1168838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1169709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179851");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182257");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183069");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183277");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183279");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183311");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183319");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183321");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184196");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184943");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185980");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186352");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186401");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186681");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YMMFY2OXW23MB2M73JXBDJKJD5G5YCOX/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ecc4ff78");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19769");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-24586");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-24587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-24588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25672");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26139");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26147");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27170");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27171");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35519");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36310");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36311");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36312");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36322");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20268");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-23134");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27363");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27364");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27365");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28038");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28375");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28660");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28971");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29264");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29265");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29647");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32399");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33034");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33200");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3428");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3444");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3483");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3489");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3490");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3491");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28660");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-18814");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux eBPF ALU32 32-bit Invalid Bounds Tracking LPE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-64kb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-64kb-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-64kb-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-64kb-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-rebuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

pkgs = [
    {'reference':'cluster-md-kmp-64kb-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cluster-md-kmp-default-5.3.18-59.5.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cluster-md-kmp-preempt-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cluster-md-kmp-preempt-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-64kb-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-default-5.3.18-59.5.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-preempt-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-preempt-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-64kb-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-default-5.3.18-59.5.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-preempt-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-preempt-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-devel-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-extra-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-livepatch-devel-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-optional-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-livepatch-devel-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-5.3.18-59.5.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-base-5.3.18-59.5.2.18.2.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-base-rebuild-5.3.18-59.5.2.18.2.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-devel-5.3.18-59.5.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-extra-5.3.18-59.5.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-livepatch-5.3.18-59.5.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-livepatch-devel-5.3.18-59.5.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-optional-5.3.18-59.5.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-5.3.18-59.5.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kvmsmall-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kvmsmall-devel-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kvmsmall-livepatch-devel-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-macros-5.3.18-59.5.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-obs-build-5.3.18-59.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-obs-qa-5.3.18-59.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-devel-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-devel-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-extra-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-extra-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-livepatch-devel-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-livepatch-devel-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-optional-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-optional-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-source-5.3.18-59.5.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-source-vanilla-5.3.18-59.5.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-syms-5.3.18-59.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-5.3.18-59.5.2', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-64kb-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-default-5.3.18-59.5.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-preempt-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-preempt-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-64kb-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-default-5.3.18-59.5.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-preempt-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-preempt-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-64kb-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-default-5.3.18-59.5.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-preempt-5.3.18-59.5.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-preempt-5.3.18-59.5.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-64kb / cluster-md-kmp-default / cluster-md-kmp-preempt / etc');
}
