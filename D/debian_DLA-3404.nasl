#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3404. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(175925);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/17");

  script_cve_id(
    "CVE-2022-2196",
    "CVE-2022-3424",
    "CVE-2022-3707",
    "CVE-2022-4129",
    "CVE-2022-4379",
    "CVE-2023-0045",
    "CVE-2023-0458",
    "CVE-2023-0459",
    "CVE-2023-0461",
    "CVE-2023-1073",
    "CVE-2023-1074",
    "CVE-2023-1076",
    "CVE-2023-1077",
    "CVE-2023-1078",
    "CVE-2023-1079",
    "CVE-2023-1118",
    "CVE-2023-1281",
    "CVE-2023-1513",
    "CVE-2023-1611",
    "CVE-2023-1670",
    "CVE-2023-1829",
    "CVE-2023-1855",
    "CVE-2023-1859",
    "CVE-2023-1872",
    "CVE-2023-1989",
    "CVE-2023-1990",
    "CVE-2023-1998",
    "CVE-2023-2162",
    "CVE-2023-2194",
    "CVE-2023-22998",
    "CVE-2023-23004",
    "CVE-2023-23559",
    "CVE-2023-25012",
    "CVE-2023-26545",
    "CVE-2023-28328",
    "CVE-2023-28466",
    "CVE-2023-30456"
  );

  script_name(english:"Debian DLA-3404-1 : linux-5.10 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3404 advisory.

  - A regression exists in the Linux Kernel within KVM: nVMX that allowed for speculative execution attacks.
    L2 can carry out Spectre v2 attacks on L1 due to L1 thinking it doesn't need retpolines or IBPB after
    running L2 due to KVM (L0) advertising eIBRS support to L1. An attacker at L2 with code execution can
    execute code on an indirect branch on the host machine. We recommend upgrading to Kernel 6.2 or past
    commit 2e7eab81425a (CVE-2022-2196)

  - A use-after-free flaw was found in the Linux kernel's SGI GRU driver in the way the first
    gru_file_unlocked_ioctl function is called by the user, where a fail pass occurs in the
    gru_check_chiplet_assignment function. This flaw allows a local user to crash or potentially escalate
    their privileges on the system. (CVE-2022-3424)

  - A double-free memory flaw was found in the Linux kernel. The Intel GVT-g graphics driver triggers VGA card
    system resource overload, causing a fail in the intel_gvt_dma_map_guest_page function. This issue could
    allow a local user to crash the system. (CVE-2022-3707)

  - A flaw was found in the Linux kernel's Layer 2 Tunneling Protocol (L2TP). A missing lock when clearing
    sk_user_data can lead to a race condition and NULL pointer dereference. A local user could use this flaw
    to potentially crash the system causing a denial of service. (CVE-2022-4129)

  - A use-after-free vulnerability was found in __nfs42_ssc_open() in fs/nfs/nfs4file.c in the Linux kernel.
    This flaw allows an attacker to conduct a remote denial (CVE-2022-4379)

  - The current implementation of the prctl syscall does not issue an IBPB immediately during the syscall. The
    ib_prctl_set function updates the Thread Information Flags (TIFs) for the task and updates the SPEC_CTRL
    MSR on the function __speculation_ctrl_update, but the IBPB is only issued on the next schedule, when the
    TIF bits are checked. This leaves the victim vulnerable to values already injected on the BTB, prior to
    the prctl syscall. The patch that added the support for the conditional mitigation via prctl
    (ib_prctl_set) dates back to the kernel 4.9.176. We recommend upgrading past commit
    a664ec9158eeddd75121d39c9a0758016097fa96 (CVE-2023-0045)

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

  - A use-after-free vulnerability in the Linux Kernel io_uring system can be exploited to achieve local
    privilege escalation. The io_file_get_fixed function lacks the presence of ctx->uring_lock which can lead
    to a Use-After-Free vulnerability due a race condition with fixed files getting unregistered. We recommend
    upgrading past commit da24142b1ef9fd5d36b76e36bab328a5b27523e8. (CVE-2023-1872)

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

  - In the Linux kernel before 6.0.3, drivers/gpu/drm/virtio/virtgpu_object.c misinterprets the
    drm_gem_shmem_get_sg_table return value (expects it to be NULL in the error case, whereas it is actually
    an error pointer). (CVE-2023-22998)

  - In the Linux kernel before 5.19, drivers/gpu/drm/arm/malidp_planes.c misinterprets the get_sg_table return
    value (expects it to be NULL in the error case, whereas it is actually an error pointer). (CVE-2023-23004)

  - In rndis_query_oid in drivers/net/wireless/rndis_wlan.c in the Linux kernel through 6.1.5, there is an
    integer overflow in an addition. (CVE-2023-23559)

  - The Linux kernel through 6.1.9 has a Use-After-Free in bigben_remove in drivers/hid/hid-bigbenff.c via a
    crafted USB device because the LED controllers remain registered for too long. (CVE-2023-25012)

  - In the Linux kernel before 6.1.13, there is a double free in net/mpls/af_mpls.c upon an allocation failure
    (for registering the sysctl table under a new location) during the renaming of a device. (CVE-2023-26545)

  - A NULL pointer dereference flaw was found in the az6027 driver in drivers/media/usb/dev-usb/az6027.c in
    the Linux Kernel. The message from user space is not checked properly before transferring into the device.
    This flaw allows a local user to crash the system or potentially cause a denial of service.
    (CVE-2023-28328)

  - do_tls_getsockopt in net/tls/tls_main.c in the Linux kernel through 6.2.6 lacks a lock_sock call, leading
    to a race condition (with a resultant use-after-free or NULL pointer dereference). (CVE-2023-28466)

  - An issue was discovered in arch/x86/kvm/vmx/nested.c in the Linux kernel before 6.2.8. nVMX on x86_64
    lacks consistency checks for CR0 and CR4. (CVE-2023-30456)

  - AMD recommends using a software mitigation for this issue, which the kernel is enabling by default. The
    Linux kernel will use the generic retpoline software mitigation, instead of the specialized AMD one, on
    AMD instances (*5a*). This is done by default, and no administrator action is needed. (CVE-2021-26341)
    (CVE-2023-0459)

  - Use after free in xen_9pfs_front_remove due to race condition (CVE-2023-1859)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=989705");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux-5.10");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3404");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2196");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3424");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3707");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4129");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4379");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0045");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0458");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0459");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0461");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1073");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1074");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1076");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1077");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1078");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1079");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1118");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1281");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1513");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1611");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1670");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1829");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1855");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1859");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1872");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1989");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1990");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1998");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2162");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2194");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-22998");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23004");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23559");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-25012");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-26545");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28328");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28466");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-30456");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux-5.10");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux-5.10 packages.

For Debian 10 buster, these problems have been fixed in version 5.10.178-3~deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0045");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2196");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.22");
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
    {'release': '10.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-armmp-lpae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-rt-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-686', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-686-pae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-amd64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-arm64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-armmp-lpae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-cloud-amd64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-cloud-arm64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-common', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-common-rt', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-686-pae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-amd64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-arm64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-686', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-686-pae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-amd64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-arm64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-armmp-lpae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-cloud-amd64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-cloud-arm64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-common', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-common-rt', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-686-pae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-amd64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-arm64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-686', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-686-pae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-amd64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-arm64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-armmp-lpae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-cloud-amd64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-cloud-arm64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-common', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-common-rt', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-rt-686-pae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-rt-amd64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-rt-arm64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-rt-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-686', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-686-pae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-amd64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-arm64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-armmp-lpae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-cloud-amd64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-cloud-arm64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-common', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-common-rt', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-rt-686-pae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-rt-amd64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-rt-arm64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-rt-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-686', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-686-pae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-amd64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-arm64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-armmp-lpae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-cloud-amd64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-cloud-arm64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-common', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-common-rt', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-rt-686-pae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-rt-amd64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-rt-arm64', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-rt-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-686-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-686-pae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-amd64-signed-template', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-arm64-signed-template', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-lpae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-lpae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-cloud-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-cloud-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-i386-signed-template', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-686-pae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-armmp-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-pae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-pae-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-amd64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-arm64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp-lpae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp-lpae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-amd64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-arm64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-686-pae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-686-pae-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-amd64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-arm64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-armmp-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-pae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-pae-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-amd64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-arm64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp-lpae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp-lpae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-amd64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-arm64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-686-pae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-686-pae-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-amd64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-arm64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-armmp-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-686-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-686-pae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-686-pae-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-686-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-amd64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-arm64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-armmp-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-armmp-lpae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-armmp-lpae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-cloud-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-cloud-amd64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-cloud-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-cloud-arm64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-686-pae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-686-pae-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-amd64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-arm64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-armmp-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-686-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-686-pae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-686-pae-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-686-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-amd64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-arm64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-armmp-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-armmp-lpae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-armmp-lpae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-cloud-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-cloud-amd64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-cloud-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-cloud-arm64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-686-pae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-686-pae-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-amd64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-arm64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-armmp-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-686-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-686-pae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-686-pae-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-686-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-amd64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-arm64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-armmp-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-armmp-lpae', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-armmp-lpae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-cloud-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-cloud-amd64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-cloud-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-cloud-arm64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-rt-686-pae-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-rt-686-pae-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-rt-amd64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-rt-amd64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-rt-arm64-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-rt-arm64-unsigned', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-rt-armmp', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-rt-armmp-dbg', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.17', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.19', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.20', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.21', 'reference': '5.10.178-3~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.22', 'reference': '5.10.178-3~deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-config-5.10 / linux-doc-5.10 / linux-headers-5.10-armmp / etc');
}
