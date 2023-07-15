#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3403. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(175926);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/17");

  script_cve_id(
    "CVE-2022-2873",
    "CVE-2022-3424",
    "CVE-2022-3545",
    "CVE-2022-3707",
    "CVE-2022-4744",
    "CVE-2022-36280",
    "CVE-2022-41218",
    "CVE-2022-45934",
    "CVE-2022-47929",
    "CVE-2023-0045",
    "CVE-2023-0266",
    "CVE-2023-0394",
    "CVE-2023-0458",
    "CVE-2023-0459",
    "CVE-2023-0461",
    "CVE-2023-1073",
    "CVE-2023-1074",
    "CVE-2023-1078",
    "CVE-2023-1079",
    "CVE-2023-1118",
    "CVE-2023-1281",
    "CVE-2023-1513",
    "CVE-2023-1670",
    "CVE-2023-1829",
    "CVE-2023-1855",
    "CVE-2023-1859",
    "CVE-2023-1989",
    "CVE-2023-1990",
    "CVE-2023-1998",
    "CVE-2023-2162",
    "CVE-2023-2194",
    "CVE-2023-23454",
    "CVE-2023-23455",
    "CVE-2023-23559",
    "CVE-2023-26545",
    "CVE-2023-28328",
    "CVE-2023-30456",
    "CVE-2023-30772"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"Debian DLA-3403-1 : linux - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3403 advisory.

  - An out-of-bounds memory access flaw was found in the Linux kernel Intel's iSMT SMBus host controller
    driver in the way a user triggers the I2C_SMBUS_BLOCK_DATA (with the ioctl I2C_SMBUS) with malicious input
    data. This flaw allows a local user to crash the system. (CVE-2022-2873)

  - A use-after-free flaw was found in the Linux kernel's SGI GRU driver in the way the first
    gru_file_unlocked_ioctl function is called by the user, where a fail pass occurs in the
    gru_check_chiplet_assignment function. This flaw allows a local user to crash or potentially escalate
    their privileges on the system. (CVE-2022-3424)

  - A vulnerability has been found in Linux Kernel and classified as critical. Affected by this vulnerability
    is the function area_cache_get of the file drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c of the
    component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this
    issue. The identifier VDB-211045 was assigned to this vulnerability. (CVE-2022-3545)

  - An out-of-bounds(OOB) memory access vulnerability was found in vmwgfx driver in
    drivers/gpu/vmxgfx/vmxgfx_kms.c in GPU component in the Linux kernel with device file '/dev/dri/renderD128
    (or Dxxx)'. This flaw allows a local attacker with a user account on the system to gain privilege, causing
    a denial of service(DoS). (CVE-2022-36280)

  - A double-free memory flaw was found in the Linux kernel. The Intel GVT-g graphics driver triggers VGA card
    system resource overload, causing a fail in the intel_gvt_dma_map_guest_page function. This issue could
    allow a local user to crash the system. (CVE-2022-3707)

  - In drivers/media/dvb-core/dmxdev.c in the Linux kernel through 5.19.10, there is a use-after-free caused
    by refcount races, affecting dvb_demux_open and dvb_dmxdev_release. (CVE-2022-41218)

  - An issue was discovered in the Linux kernel through 6.0.10. l2cap_config_req in net/bluetooth/l2cap_core.c
    has an integer wraparound via L2CAP_CONF_REQ packets. (CVE-2022-45934)

  - A double-free flaw was found in the Linux kernel's TUN/TAP device driver functionality in how a user
    registers the device when the register_netdevice function fails (NETDEV_REGISTER notifier). This flaw
    allows a local user to crash or potentially escalate their privileges on the system. (CVE-2022-4744)

  - In the Linux kernel before 6.1.6, a NULL pointer dereference bug in the traffic control subsystem allows
    an unprivileged user to trigger a denial of service (system crash) via a crafted traffic control
    configuration that is set up with tc qdisc and tc class commands. This affects qdisc_graft in
    net/sched/sch_api.c. (CVE-2022-47929)

  - The current implementation of the prctl syscall does not issue an IBPB immediately during the syscall. The
    ib_prctl_set function updates the Thread Information Flags (TIFs) for the task and updates the SPEC_CTRL
    MSR on the function __speculation_ctrl_update, but the IBPB is only issued on the next schedule, when the
    TIF bits are checked. This leaves the victim vulnerable to values already injected on the BTB, prior to
    the prctl syscall. The patch that added the support for the conditional mitigation via prctl
    (ib_prctl_set) dates back to the kernel 4.9.176. We recommend upgrading past commit
    a664ec9158eeddd75121d39c9a0758016097fa96 (CVE-2023-0045)

  - A use after free vulnerability exists in the ALSA PCM package in the Linux Kernel.
    SNDRV_CTL_IOCTL_ELEM_{READ|WRITE}32 is missing locks that can be used in a use-after-free that can result
    in a priviledge escalation to gain ring0 access from the system user. We recommend upgrading past commit
    56b88b50565cd8b946a2d00b0c83927b7ebb055e (CVE-2023-0266)

  - A NULL pointer dereference flaw was found in rawv6_push_pending_frames in net/ipv6/raw.c in the network
    subcomponent in the Linux kernel. This flaw causes the system to crash. (CVE-2023-0394)

  - A speculative pointer dereference problem exists in the Linux Kernel on the do_prlimit() function. The
    resource argument value is controlled and is used in pointer arithmetic for the 'rlim' variable and can be
    used to leak the contents. We recommend upgrading past version 6.1.8 or commit
    739790605705ddcf18f21782b9c99ad7d53a8c11 (CVE-2023-0458)

  - There is a use-after-free vulnerability in the Linux Kernel which can be exploited to achieve local
    privilege escalation. To reach the vulnerability kernel configuration flag CONFIG_TLS or
    CONFIG_XFRM_ESPINTCP has to be configured, but the operation does not require any privilege. There is a
    use-after-free bug of icsk_ulp_data of a struct inet_connection_sock. When CONFIG_TLS is enabled, user can
    install a tls context (struct tls_context) on a connected tcp socket. The context is not cleared if this
    socket is disconnected and reused as a listener. If a new socket is created from the listener, the context
    is inherited and vulnerable. The setsockopt TCP_ULP operation does not require any privilege. We recommend
    upgrading past commit 2c02d41d71f90a5168391b6a5f2954112ba2307c (CVE-2023-0461)

  - A memory corruption flaw was found in the Linux kernel's human interface device (HID) subsystem in how a
    user inserts a malicious USB device. This flaw allows a local user to crash or potentially escalate their
    privileges on the system. (CVE-2023-1073)

  - A memory leak flaw was found in the Linux kernel's Stream Control Transmission Protocol. This issue may
    occur when a user starts a malicious networking service and someone connects to this service. This could
    allow a local user to starve resources, causing a denial of service. (CVE-2023-1074)

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

  - A flaw was found in KVM. When calling the KVM_GET_DEBUGREGS ioctl, on 32-bit systems, there might be some
    uninitialized portions of the kvm_debugregs structure that could be copied to userspace, causing an
    information leak. (CVE-2023-1513)

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

  - A use-after-free flaw was found in btsdio_remove in drivers\bluetooth\btsdio.c in the Linux Kernel. In
    this flaw, a call to btsdio_remove with an unfinished job, may cause a race problem leading to a UAF on
    hdev devices. (CVE-2023-1989)

  - A use-after-free flaw was found in ndlc_remove in drivers/nfc/st-nci/ndlc.c in the Linux Kernel. This flaw
    could allow an attacker to crash the system due to a race problem. (CVE-2023-1990)

  - The Linux kernel allows userspace processes to enable mitigations by calling prctl with
    PR_SET_SPECULATION_CTRL which disables the speculation feature as well as by using seccomp. We had noticed
    that on VMs of at least one major cloud provider, the kernel still left the victim process exposed to
    attacks in some cases even after enabling the spectre-BTI mitigation with prctl. The same behavior can be
    observed on a bare-metal machine when forcing the mitigation to IBRS on boot command line. This happened
    because when plain IBRS was enabled (not enhanced IBRS), the kernel had some logic that determined that
    STIBP was not needed. The IBRS bit implicitly protects against cross-thread branch target injection.
    However, with legacy IBRS, the IBRS bit was cleared on returning to userspace, due to performance reasons,
    which disabled the implicit STIBP and left userspace threads vulnerable to cross-thread branch target
    injection against which STIBP protects. (CVE-2023-1998)

  - A use-after-free vulnerability was found in iscsi_sw_tcp_session_create in drivers/scsi/iscsi_tcp.c in
    SCSI sub-component in the Linux Kernel. In this flaw an attacker could leak kernel internal information.
    (CVE-2023-2162)

  - An out-of-bounds write vulnerability was found in the Linux kernel's SLIMpro I2C device driver. The
    userspace data->block[0] variable was not capped to a number between 0-255 and was used as the size of a
    memcpy, possibly writing beyond the end of dma_buffer. This flaw could allow a local privileged user to
    crash the system or potentially achieve code execution. (CVE-2023-2194)

  - cbq_classify in net/sched/sch_cbq.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service (slab-out-of-bounds read) because of type confusion (non-negative numbers can sometimes
    indicate a TC_ACT_SHOT condition rather than valid classification results). (CVE-2023-23454)

  - atm_tc_enqueue in net/sched/sch_atm.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition
    rather than valid classification results). (CVE-2023-23455)

  - In rndis_query_oid in drivers/net/wireless/rndis_wlan.c in the Linux kernel through 6.1.5, there is an
    integer overflow in an addition. (CVE-2023-23559)

  - In the Linux kernel before 6.1.13, there is a double free in net/mpls/af_mpls.c upon an allocation failure
    (for registering the sysctl table under a new location) during the renaming of a device. (CVE-2023-26545)

  - A NULL pointer dereference flaw was found in the az6027 driver in drivers/media/usb/dev-usb/az6027.c in
    the Linux Kernel. The message from user space is not checked properly before transferring into the device.
    This flaw allows a local user to crash the system or potentially cause a denial of service.
    (CVE-2023-28328)

  - An issue was discovered in arch/x86/kvm/vmx/nested.c in the Linux kernel before 6.2.8. nVMX on x86_64
    lacks consistency checks for CR0 and CR4. (CVE-2023-30456)

  - The Linux kernel before 6.2.9 has a race condition and resultant use-after-free in
    drivers/power/supply/da9150-charger.c if a physically proximate attacker unplugs a device.
    (CVE-2023-30772)

  - AMD recommends using a software mitigation for this issue, which the kernel is enabling by default. The
    Linux kernel will use the generic retpoline software mitigation, instead of the specialized AMD one, on
    AMD instances (*5a*). This is done by default, and no administrator action is needed. (CVE-2021-26341)
    (CVE-2023-0459)

  - Use after free in xen_9pfs_front_remove due to race condition (CVE-2023-1859)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=825141");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3403");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2873");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3424");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3545");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36280");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3707");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41218");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45934");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4744");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47929");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0045");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0266");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0394");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0458");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0459");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0461");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1073");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1074");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1078");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1079");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1118");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1281");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1513");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1670");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1829");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1855");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1859");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1989");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1990");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1998");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2162");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2194");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23454");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23455");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23559");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-26545");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28328");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-30456");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-30772");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux packages.

For Debian 10 buster, these problems have been fixed in version 4.19.282-1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0045");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-23559");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbpf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbpf4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.19.0-19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'hyperv-daemons', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'libbpf-dev', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'libbpf4.19', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'libcpupower-dev', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'libcpupower1', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-arm', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-x86', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-config-4.19', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-cpupower', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-doc-4.19', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-686', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-686-pae', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-amd64', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-arm64', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-armhf', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-i386', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-amd64', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-arm64', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-armmp', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-armmp-lpae', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-cloud-amd64', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-common', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-common-rt', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-686-pae', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-amd64', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-arm64', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-armmp', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-pae-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-pae-unsigned', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-unsigned', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-amd64-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-amd64-unsigned', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-arm64-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-arm64-unsigned', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp-lpae', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp-lpae-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-cloud-amd64-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-cloud-amd64-unsigned', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-686-pae-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-686-pae-unsigned', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-amd64-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-amd64-unsigned', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-arm64-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-arm64-unsigned', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-armmp', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-armmp-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-kbuild-4.19', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-libc-dev', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-perf-4.19', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-source-4.19', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-support-4.19.0-19', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'usbip', 'reference': '4.19.282-1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hyperv-daemons / libbpf-dev / libbpf4.19 / libcpupower-dev / etc');
}
