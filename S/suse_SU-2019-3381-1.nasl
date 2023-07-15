#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:3381-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(132394);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-14895", "CVE-2019-14901", "CVE-2019-15213", "CVE-2019-15916", "CVE-2019-16231", "CVE-2019-17055", "CVE-2019-18660", "CVE-2019-18683", "CVE-2019-18805", "CVE-2019-18808", "CVE-2019-18809", "CVE-2019-19049", "CVE-2019-19051", "CVE-2019-19052", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19058", "CVE-2019-19060", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19065", "CVE-2019-19066", "CVE-2019-19067", "CVE-2019-19068", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19075", "CVE-2019-19077", "CVE-2019-19227", "CVE-2019-19332", "CVE-2019-19338", "CVE-2019-19523", "CVE-2019-19524", "CVE-2019-19525", "CVE-2019-19526", "CVE-2019-19527", "CVE-2019-19528", "CVE-2019-19529", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19532", "CVE-2019-19533", "CVE-2019-19534", "CVE-2019-19535", "CVE-2019-19536", "CVE-2019-19537", "CVE-2019-19543", "CVE-2019-19767");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : kernel (SUSE-SU-2019:3381-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The SUSE Linux Enterprise 15 kernel was updated to receive various
security and bugfixes.

The following security bugs were fixed :

CVE-2019-19767: Fixed ext4_expand_extra_isize mishandles, as
demonstrated by use-after-free errors in __ext4_expand_extra_isize and
ext4_xattr_set_entry, related to fs/ext4/inode.c and fs/ext4/super.c
(bnc#1159297).

CVE-2019-18808: Fixed a memory leak in the ccp_run_sha_cmd() function
in drivers/crypto/ccp/ccp-ops.c allowed attackers to cause a denial of
service (memory consumption) (bnc#1156259).

CVE-2019-19066: Fixed memory leak in the bfad_im_get_stats() function
in drivers/scsi/bfa/bfad_attr.c that allowed attackers to cause a
denial of service (memory consumption) by triggering
bfa_port_get_stats() failures (bnc#1157303).

CVE-2019-19051: Fixed memory leak in the i2400m_op_rfkill_sw_toggle()
function in drivers/net/wimax/i2400m/op-rfkill.c that allowed
attackers to cause a denial of service (memory consumption)
(bnc#1159024).

CVE-2019-19338: There was an incomplete fix for Transaction
Asynchronous Abort (TAA) (bsc#1158954).

CVE-2019-19332: There was an OOB memory write via
kvm_dev_ioctl_get_cpuid (bsc#1158827).

CVE-2019-19537: There was a race condition bug that could have been
caused by a malicious USB device in the USB character device driver
layer (bnc#1158904).

CVE-2019-19535: There was an info-leak bug that could have been caused
by a malicious USB device in the
drivers/net/can/usb/peak_usb/pcan_usb_fd.c driver (bnc#1158903).

CVE-2019-19527: There was a use-after-free bug that could have been
caused by a malicious USB device in the drivers/hid/usbhid/hiddev.c
driver (bnc#1158900).

CVE-2019-19526: There was a use-after-free bug that could have been
caused by a malicious USB device in the drivers/nfc/pn533/usb.c driver
(bnc#1158893).

CVE-2019-19533: There was an info-leak bug that could have been caused
by a malicious USB device in the
drivers/media/usb/ttusb-dec/ttusb_dec.c driver (bnc#1158834).

CVE-2019-19532: There were multiple out-of-bounds write bugs that
could have been caused by a malicious USB device in the Linux kernel
HID drivers (bnc#1158824).

CVE-2019-19523: There was a use-after-free bug that could have been
caused by a malicious USB device in the drivers/usb/misc/adutux.c
driver (bnc#1158823).

CVE-2019-15213: An issue was discovered in the Linux kernel, there was
a use-after-free caused by a malicious USB device in the
drivers/media/usb/dvb-usb/dvb-usb-init.c driver (bnc#1146544).

CVE-2019-19531: There was a use-after-free bug that can be caused by a
malicious USB device in the drivers/usb/misc/yurex.c driver
(bnc#1158445).

CVE-2019-19543: There was a use-after-free in serial_ir_init_module()
in drivers/media/rc/serial_ir.c (bnc#1158427).

CVE-2019-19525: There was a use-after-free bug that can be caused by a
malicious USB device in the drivers/net/ieee802154/atusb.c driver
(bnc#1158417).

CVE-2019-19530: There was a use-after-free bug that can be caused by a
malicious USB device in the drivers/usb/class/cdc-acm.c driver
(bnc#1158410).

CVE-2019-19536: There was an info-leak bug that can be caused by a
malicious USB device in the
drivers/net/can/usb/peak_usb/pcan_usb_pro.c driver (bnc#1158394).

CVE-2019-19524: There was a use-after-free bug that can be caused by a
malicious USB device in the drivers/input/ff-memless.c driver
(bnc#1158413).

CVE-2019-19528: There was a use-after-free bug that can be caused by a
malicious USB device in the drivers/usb/misc/iowarrior.c driver
(bnc#1158407).

CVE-2019-19534: There was an info-leak bug that can be caused by a
malicious USB device in the
drivers/net/can/usb/peak_usb/pcan_usb_core.c driver (bnc#1158398).

CVE-2019-19529: There was a use-after-free bug that can be caused by a
malicious USB device in the drivers/net/can/usb/mcba_usb.c driver
(bnc#1158381).

CVE-2019-14901: A heap overflow flaw was found in the Linux kernel in
Marvell WiFi chip driver. The vulnerability allowed a remote attacker
to cause a system crash, resulting in a denial of service, or execute
arbitrary code. The highest threat with this vulnerability is with the
availability of the system. If code execution occurs, the code will
run with the permissions of root. This will affect both
confidentiality and integrity of files on the system (bnc#1157042).

CVE-2019-14895: A heap-based buffer overflow was discovered in the
Linux kernel in Marvell WiFi chip driver. The flaw could occur when
the station attempts a connection negotiation during the handling of
the remote devices country settings. This could have allowed the
remote device to cause a denial of service (system crash) or possibly
execute arbitrary code (bnc#1157158).

CVE-2019-18660: The Linux kernel on powerpc allowed Information
Exposure because the Spectre-RSB mitigation is not in place for all
applicable CPUs. This is related to arch/powerpc/kernel/entry_64.S and
arch/powerpc/kernel/security.c (bnc#1157038).

CVE-2019-18683: An issue was discovered in
drivers/media/platform/vivid in the Linux kernel. It is exploitable
for privilege escalation on some Linux distributions where local users
have /dev/video0 access, but only if the driver happens to be loaded.
There are multiple race conditions during streaming stopping in this
driver (part of the V4L2 subsystem). These issues are caused by wrong
mutex locking in vivid_stop_generating_vid_cap(),
vivid_stop_generating_vid_out(), sdr_cap_stop_streaming(), and the
corresponding kthreads. At least one of these race conditions leads to
a use-after-free (bnc#1155897).

CVE-2019-18809: A memory leak in the af9005_identify_state() function
in drivers/media/usb/dvb-usb/af9005.c in the Linux kernel allowed
attackers to cause a denial of service (memory consumption)
(bnc#1156258).

CVE-2019-19062: A memory leak in the crypto_report() function in
crypto/crypto_user_base.c in the Linux kernel allowed attackers to
cause a denial of service (memory consumption) by triggering
crypto_report_alg() failures (bnc#1157333).

CVE-2019-19057: Two memory leaks in the mwifiex_pcie_init_evt_ring()
function in drivers/net/wireless/marvell/mwifiex/pcie.c in the Linux
kernel allowed attackers to cause a denial of service (memory
consumption) by triggering mwifiex_map_pci_memory() failures
(bnc#1157197).

CVE-2019-19056: A memory leak in the mwifiex_pcie_alloc_cmdrsp_buf()
function in drivers/net/wireless/marvell/mwifiex/pcie.c in the Linux
kernel allowed attackers to cause a denial of service (memory
consumption) by triggering mwifiex_map_pci_memory() failures
(bnc#1157197).

CVE-2019-19068: A memory leak in the rtl8xxxu_submit_int_urb()
function in drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu_core.c in
the Linux kernel allowed attackers to cause a denial of service
(memory consumption) by triggering usb_submit_urb() failures
(bnc#1157307).

CVE-2019-19063: Two memory leaks in the rtl_usb_probe() function in
drivers/net/wireless/realtek/rtlwifi/usb.c in the Linux kernel allowed
attackers to cause a denial of service (memory consumption)
(bnc#1157298).

CVE-2019-19227: In the AppleTalk subsystem in the Linux kernel there
was a potential NULL pointer dereference because register_snap_client
may return NULL. This will lead to denial of service in
net/appletalk/aarp.c and net/appletalk/ddp.c, as demonstrated by
unregister_snap_client (bnc#1157678).

CVE-2019-19065: A memory leak in the sdma_init() function in
drivers/infiniband/hw/hfi1/sdma.c in the Linux kernel allowed
attackers to cause a denial of service (memory consumption) by
triggering rhashtable_init() failures (bnc#1157191).

CVE-2019-19077: A memory leak in the bnxt_re_create_srq() function in
drivers/infiniband/hw/bnxt_re/ib_verbs.c in the Linux kernel allowed
attackers to cause a denial of service (memory consumption) by
triggering copy to udata failures (bnc#1157171).

CVE-2019-19052: A memory leak in the gs_can_open() function in
drivers/net/can/usb/gs_usb.c in the Linux kernel allowed attackers to
cause a denial of service (memory consumption) by triggering
usb_submit_urb() failures (bnc#1157324).

CVE-2019-19067: Four memory leaks in the acp_hw_init() function in
drivers/gpu/drm/amd/amdgpu/amdgpu_acp.c in the Linux kernel allowed
attackers to cause a denial of service (memory consumption) by
triggering mfd_add_hotplug_devices() or pm_genpd_add_device() failures
(bsc#1157180).

CVE-2019-19060: A memory leak in the adis_update_scan_mode() function
in drivers/iio/imu/adis_buffer.c in the Linux kernel allowed attackers
to cause a denial of service (memory consumption) (bnc#1157178).

CVE-2019-19049: A memory leak in the unittest_data_add() function in
drivers/of/unittest.c in the Linux kernel allowed attackers to cause a
denial of service (memory consumption) by triggering
of_fdt_unflatten_tree() failures (bsc#1157173).

CVE-2019-19075: A memory leak in the ca8210_probe() function in
drivers/net/ieee802154/ca8210.c in the Linux kernel allowed attackers
to cause a denial of service (memory consumption) by triggering
ca8210_get_platform_data() failures (bnc#1157162).

CVE-2019-19058: A memory leak in the alloc_sgtable() function in
drivers/net/wireless/intel/iwlwifi/fw/dbg.c in the Linux kernel
allowed attackers to cause a denial of service (memory consumption) by
triggering alloc_page() failures (bnc#1157145).

CVE-2019-19074: A memory leak in the ath9k_wmi_cmd() function in
drivers/net/wireless/ath/ath9k/wmi.c in the Linux kernel allowed
attackers to cause a denial of service (memory consumption)
(bnc#1157143).

CVE-2019-19073: Memory leaks in
drivers/net/wireless/ath/ath9k/htc_hst.c in the Linux kernel allowed
attackers to cause a denial of service (memory consumption) by
triggering wait_for_completion_timeout() failures. This affects the
htc_config_pipe_credits() function, the htc_setup_complete() function,
and the htc_connect_service() function (bnc#1157070).

CVE-2019-15916: An issue was discovered in the Linux kernel There was
a memory leak in register_queue_kobjects() in net/core/net-sysfs.c,
which will cause denial of service (bnc#1149448).

CVE-2019-16231: drivers/net/fjes/fjes_main.c in the Linux kernel
5.2.14 did not check the alloc_workqueue return value, leading to a
NULL pointer dereference (bnc#1150466).

CVE-2019-18805: An issue was discovered in net/ipv4/sysctl_net_ipv4.c
in the Linux kernel There was a net/ipv4/tcp_input.c signed integer
overflow in tcp_ack_update_rtt() when userspace writes a very large
integer to /proc/sys/net/ipv4/tcp_min_rtt_wlen, leading to a denial of
service or possibly unspecified other impact (bnc#1156187).

CVE-2019-17055: base_sock_create in drivers/isdn/mISDN/socket.c in the
AF_ISDN network module in the Linux kernel did not enforce
CAP_NET_RAW, which means that unprivileged users can create a raw
socket (bnc#1152782).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1046303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1078248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1089644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1108043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1115026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1117169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1120853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1131107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1138039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1142095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1143706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1143959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1144333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1146519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1146544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1149448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1150466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1151548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1151900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1152631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1152782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157499"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1159024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1159297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-14895/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-14901/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-15213/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-15916/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-16231/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17055/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-18660/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-18683/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-18805/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-18808/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-18809/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19049/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19051/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19052/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19056/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19057/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19058/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19060/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19062/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19063/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19065/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19066/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19067/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19068/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19073/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19074/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19075/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19077/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19227/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19332/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19338/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19523/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19524/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19525/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19526/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19527/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19528/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19529/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19530/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19531/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19532/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19533/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19534/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19535/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19536/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19537/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19543/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19767/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20193381-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1dfab50f"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15:zypper in -t patch
SUSE-SLE-Product-WE-15-2019-3381=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-3381=1

SUSE Linux Enterprise Module for Live Patching 15:zypper in -t patch
SUSE-SLE-Module-Live-Patching-15-2019-3381=1

SUSE Linux Enterprise Module for Legacy Software 15:zypper in -t patch
SUSE-SLE-Module-Legacy-15-2019-3381=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2019-3381=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-3381=1

SUSE Linux Enterprise High Availability 15:zypper in -t patch
SUSE-SLE-Product-HA-15-2019-3381=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kselftests-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kselftests-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-man-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-debugsource-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-default-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-default-base-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-default-base-debuginfo-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-default-debuginfo-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-default-debugsource-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-default-devel-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-default-devel-debuginfo-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-obs-build-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-obs-build-debugsource-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-obs-qa-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-syms-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-vanilla-base-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-vanilla-base-debuginfo-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-vanilla-debuginfo-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-vanilla-debugsource-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kselftests-kmp-default-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kselftests-kmp-default-debuginfo-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"reiserfs-kmp-default-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"reiserfs-kmp-default-debuginfo-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"s390x", reference:"kernel-default-man-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-debugsource-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-default-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-default-base-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-default-base-debuginfo-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-default-debuginfo-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-default-debugsource-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-default-devel-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-default-devel-debuginfo-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-obs-build-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-obs-build-debugsource-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-obs-qa-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-syms-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-vanilla-base-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-vanilla-base-debuginfo-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-vanilla-debuginfo-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-vanilla-debugsource-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kselftests-kmp-default-4.12.14-150.47.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kselftests-kmp-default-debuginfo-4.12.14-150.47.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
