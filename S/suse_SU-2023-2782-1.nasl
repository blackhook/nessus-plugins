#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2782-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(177994);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/05");

  script_cve_id(
    "CVE-2022-4269",
    "CVE-2022-45884",
    "CVE-2022-45885",
    "CVE-2022-45886",
    "CVE-2022-45887",
    "CVE-2022-45919",
    "CVE-2023-1077",
    "CVE-2023-1079",
    "CVE-2023-1249",
    "CVE-2023-1380",
    "CVE-2023-1382",
    "CVE-2023-2002",
    "CVE-2023-2124",
    "CVE-2023-2156",
    "CVE-2023-2162",
    "CVE-2023-2269",
    "CVE-2023-2483",
    "CVE-2023-2513",
    "CVE-2023-3006",
    "CVE-2023-3141",
    "CVE-2023-3161",
    "CVE-2023-21102",
    "CVE-2023-28410",
    "CVE-2023-30456",
    "CVE-2023-31084",
    "CVE-2023-31436",
    "CVE-2023-32233",
    "CVE-2023-33288",
    "CVE-2023-35788",
    "CVE-2023-35823",
    "CVE-2023-35828"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2782-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2023:2782-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:2782-1 advisory.

  - A flaw was found in the Linux kernel Traffic Control (TC) subsystem. Using a specific networking
    configuration (redirecting egress packets to ingress using TC action mirred) a local unprivileged user
    could trigger a CPU soft lockup (ABBA deadlock) when the transport protocol in use (TCP or SCTP) does a
    retransmission, resulting in a denial of service condition. (CVE-2022-4269)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvbdev.c has a use-
    after-free, related to dvb_register_device dynamically allocating fops. (CVE-2022-45884)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvb_frontend.c has a
    race condition that can cause a use-after-free when a device is disconnected. (CVE-2022-45885)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvb_net.c has a
    .disconnect versus dvb_device_open race condition that leads to a use-after-free. (CVE-2022-45886)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/usb/ttusb-dec/ttusb_dec.c has a
    memory leak because of the lack of a dvb_frontend_detach call. (CVE-2022-45887)

  - An issue was discovered in the Linux kernel through 6.0.10. In drivers/media/dvb-core/dvb_ca_en50221.c, a
    use-after-free can occur is there is a disconnect after an open, because of the lack of a wait_event.
    (CVE-2022-45919)

  - In the Linux kernel, pick_next_rt_entity() may return a type confused entry, not detected by the BUG_ON
    condition, as the confused entry will not be NULL, but list_head.The buggy error condition would lead to a
    type confused entry with the list head,which would then be used as a type confused sched_rt_entity,causing
    memory corruption. (CVE-2023-1077)

  - A flaw was found in the Linux kernel. A use-after-free may be triggered in asus_kbd_backlight_set when
    plugging/disconnecting in a malicious USB device, which advertises itself as an Asus device. Similarly to
    the previous known CVE-2023-25012, but in asus devices, the work_struct may be scheduled by the LED
    controller while the device is disconnecting, triggering a use-after-free on the struct asus_kbd_leds *led
    structure. A malicious USB device may exploit the issue to cause memory corruption with controlled data.
    (CVE-2023-1079)

  - A use-after-free flaw was found in the Linux kernel's core dump subsystem. This flaw allows a local user
    to crash the system. Only if patch 390031c94211 (coredump: Use the vma snapshot in fill_files_note) not
    applied yet, then kernel could be affected. (CVE-2023-1249)

  - A slab-out-of-bound read problem was found in brcmf_get_assoc_ies in
    drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c in the Linux Kernel. This issue could occur
    when assoc_info->req_len data is bigger than the size of the buffer, defined as WL_EXTRA_BUF_MAX, leading
    to a denial of service. (CVE-2023-1380)

  - A data race flaw was found in the Linux kernel, between where con is allocated and con->sock is set. This
    issue leads to a NULL pointer dereference when accessing con->sock->sk in net/tipc/topsrv.c in the tipc
    protocol in the Linux kernel. (CVE-2023-1382)

  - A vulnerability was found in the HCI sockets implementation due to a missing capability check in
    net/bluetooth/hci_sock.c in the Linux Kernel. This flaw allows an attacker to unauthorized execution of
    management commands, compromising the confidentiality, integrity, and availability of Bluetooth
    communication. (CVE-2023-2002)

  - In __efi_rt_asm_wrapper of efi-rt-wrapper.S, there is a possible bypass of shadow stack protection due to
    a logic error in the code. This could lead to local escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-260821414References: Upstream kernel (CVE-2023-21102)

  - An out-of-bounds memory access flaw was found in the Linux kernel's XFS file system in how a user restores
    an XFS image after failure (with a dirty log journal). This flaw allows a local user to crash or
    potentially escalate their privileges on the system. (CVE-2023-2124)

  - A flaw was found in the networking subsystem of the Linux kernel within the handling of the RPL protocol.
    This issue results from the lack of proper handling of user-supplied data, which can lead to an assertion
    failure. This may allow an unauthenticated remote attacker to create a denial of service condition on the
    system. (CVE-2023-2156)

  - A use-after-free vulnerability was found in iscsi_sw_tcp_session_create in drivers/scsi/iscsi_tcp.c in
    SCSI sub-component in the Linux Kernel. In this flaw an attacker could leak kernel internal information.
    (CVE-2023-2162)

  - A denial of service problem was found, due to a possible recursive locking scenario, resulting in a
    deadlock in table_clear in drivers/md/dm-ioctl.c in the Linux Kernel Device Mapper-Multipathing sub-
    component. (CVE-2023-2269)

  - A use-after-free vulnerability was found in the Linux kernel's ext4 filesystem in the way it handled the
    extra inode size for extended attributes. This flaw could allow a privileged local user to cause a system
    crash or other undefined behaviors. (CVE-2023-2513)

  - Improper restriction of operations within the bounds of a memory buffer in some Intel(R) i915 Graphics
    drivers for linux before kernel version 6.2.10 may allow an authenticated user to potentially enable
    escalation of privilege via local access. (CVE-2023-28410)

  - A known cache speculation vulnerability, known as Branch History Injection (BHI) or Spectre-BHB, becomes
    actual again for the new hw AmpereOne. Spectre-BHB is similar to Spectre v2, except that malicious code
    uses the shared branch history (stored in the CPU Branch History Buffer, or BHB) to influence mispredicted
    branches within the victim's hardware context. Once that occurs, speculation caused by the mispredicted
    branches can cause cache allocation. This issue leads to obtaining information that should not be
    accessible. (CVE-2023-3006)

  - An issue was discovered in arch/x86/kvm/vmx/nested.c in the Linux kernel before 6.2.8. nVMX on x86_64
    lacks consistency checks for CR0 and CR4. (CVE-2023-30456)

  - An issue was discovered in drivers/media/dvb-core/dvb_frontend.c in the Linux kernel 6.2. There is a
    blocking operation when a task is in !TASK_RUNNING. In dvb_frontend_get_event, wait_event_interruptible is
    called; the condition is dvb_frontend_test_event(fepriv,events). In dvb_frontend_test_event,
    down(&fepriv->sem) is called. However, wait_event_interruptible would put the process to sleep, and
    down(&fepriv->sem) may block the process. (CVE-2023-31084)

  - A use-after-free flaw was found in r592_remove in drivers/memstick/host/r592.c in media access in the
    Linux Kernel. This flaw allows a local attacker to crash the system at device disconnect, possibly leading
    to a kernel information leak. (CVE-2023-3141)

  - qfq_change_class in net/sched/sch_qfq.c in the Linux kernel before 6.2.13 allows an out-of-bounds write
    because lmax can exceed QFQ_MIN_LMAX. (CVE-2023-31436)

  - A flaw was found in the Framebuffer Console (fbcon) in the Linux Kernel. When providing font->width and
    font->height greater than 32 to fbcon_set_font, since there are no checks in place, a shift-out-of-bounds
    occurs leading to undefined behavior and possible denial of service. (CVE-2023-3161)

  - In the Linux kernel through 6.3.1, a use-after-free in Netfilter nf_tables when processing batch requests
    can be abused to perform arbitrary read and write operations on kernel memory. Unprivileged local users
    can obtain root privileges. This occurs because anonymous sets are mishandled. (CVE-2023-32233)

  - An issue was discovered in the Linux kernel before 6.2.9. A use-after-free was found in bq24190_remove in
    drivers/power/supply/bq24190_charger.c. It could allow a local attacker to crash the system due to a race
    condition. (CVE-2023-33288)

  - An issue was discovered in fl_set_geneve_opt in net/sched/cls_flower.c in the Linux kernel before 6.3.7.
    It allows an out-of-bounds write in the flower classifier code via TCA_FLOWER_KEY_ENC_OPTS_GENEVE packets.
    This may result in denial of service or privilege escalation. (CVE-2023-35788)

  - An issue was discovered in the Linux kernel before 6.3.2. A use-after-free was found in saa7134_finidev in
    drivers/media/pci/saa7134/saa7134-core.c. (CVE-2023-35823)

  - An issue was discovered in the Linux kernel before 6.3.2. A use-after-free was found in
    renesas_usb3_remove in drivers/usb/gadget/udc/renesas_usb3.c. (CVE-2023-35828)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210551");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211043");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212129");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212448");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212592");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-July/030185.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4269");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45887");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1249");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1380");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1382");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21102");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2156");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2269");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2483");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2513");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28410");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-30456");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-31084");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-31436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3161");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-32233");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-33288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35828");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1079");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-35788");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150400_15_37-rt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-5.14.21-150400.15.37.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dlm-kmp-rt-5.14.21-150400.15.37.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gfs2-kmp-rt-5.14.21-150400.15.37.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-devel-rt-5.14.21-150400.15.37.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-rt-5.14.21-150400.15.37.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-rt-devel-5.14.21-150400.15.37.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-rt_debug-5.14.21-150400.15.37.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-rt_debug-devel-5.14.21-150400.15.37.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-source-rt-5.14.21-150400.15.37.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-syms-rt-5.14.21-150400.15.37.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ocfs2-kmp-rt-5.14.21-150400.15.37.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-livepatch-5_14_21-150400_15_37-rt-1-150400.1.9.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']}
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
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-rt / dlm-kmp-rt / gfs2-kmp-rt / kernel-devel-rt / etc');
}
