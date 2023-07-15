#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2949-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(130949);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/19");

  script_cve_id(
    "CVE-2016-10906",
    "CVE-2017-18379",
    "CVE-2017-18509",
    "CVE-2017-18551",
    "CVE-2017-18595",
    "CVE-2018-12207",
    "CVE-2018-20976",
    "CVE-2019-0154",
    "CVE-2019-0155",
    "CVE-2019-9456",
    "CVE-2019-9506",
    "CVE-2019-10220",
    "CVE-2019-11135",
    "CVE-2019-13272",
    "CVE-2019-14814",
    "CVE-2019-14815",
    "CVE-2019-14816",
    "CVE-2019-14821",
    "CVE-2019-14835",
    "CVE-2019-15098",
    "CVE-2019-15211",
    "CVE-2019-15212",
    "CVE-2019-15214",
    "CVE-2019-15215",
    "CVE-2019-15216",
    "CVE-2019-15217",
    "CVE-2019-15218",
    "CVE-2019-15219",
    "CVE-2019-15220",
    "CVE-2019-15221",
    "CVE-2019-15239",
    "CVE-2019-15290",
    "CVE-2019-15291",
    "CVE-2019-15505",
    "CVE-2019-15666",
    "CVE-2019-15807",
    "CVE-2019-15902",
    "CVE-2019-15924",
    "CVE-2019-15926",
    "CVE-2019-15927",
    "CVE-2019-16232",
    "CVE-2019-16233",
    "CVE-2019-16234",
    "CVE-2019-16413",
    "CVE-2019-16995",
    "CVE-2019-17055",
    "CVE-2019-17056",
    "CVE-2019-17133",
    "CVE-2019-17666"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/10");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2019:2949-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The SUSE Linux Enterprise 12-SP3 kernel was updated to receive various
security and bugfixes.

The following security bugs were fixed :

CVE-2018-12207: Untrusted virtual machines on Intel CPUs could exploit
a race condition in the Instruction Fetch Unit of the Intel CPU to
cause a Machine Exception during Page Size Change, causing the CPU
core to be non-functional.

The Linux Kernel kvm hypervisor was adjusted to avoid page size
changes in executable pages by splitting / merging huge pages into
small pages as needed. More information can be found on
https://www.suse.com/support/kb/doc/?id=7023735 CVE-2019-16995: Fix a
memory leak in hsr_dev_finalize() if hsr_add_port failed to add a
port, which may have caused denial of service (bsc#1152685).

CVE-2019-11135: Aborting an asynchronous TSX operation on Intel CPUs
with Transactional Memory support could be used to facilitate
sidechannel information leaks out of microarchitectural buffers,
similar to the previously described 'Microarchitectural Data Sampling'
attack.

The Linux kernel was supplemented with the option to disable TSX
operation altogether (requiring CPU Microcode updates on older
systems) and better flushing of microarchitectural buffers (VERW).

The set of options available is described in our TID at
https://www.suse.com/support/kb/doc/?id=7024251
CVE-2019-16233: drivers/scsi/qla2xxx/qla_os.c did not check
the alloc_workqueue return value, leading to a NULL pointer
dereference. (bsc#1150457).

CVE-2019-10220: Added sanity checks on the pathnames passed to the
user space. (bsc#1144903).

CVE-2019-17666: rtlwifi: Fix potential overflow in P2P code
(bsc#1154372).

CVE-2019-17133: cfg80211 wireless extension did not reject a long SSID
IE, leading to a Buffer Overflow (bsc#1153158).

CVE-2019-16232: Fix a potential NULL pointer dereference in the
Marwell libertas driver (bsc#1150465).

CVE-2019-16234: iwlwifi pcie driver did not check the alloc_workqueue
return value, leading to a NULL pointer dereference. (bsc#1150452).

CVE-2019-17055: The AF_ISDN network module in the Linux kernel did not
enforce CAP_NET_RAW, which meant that unprivileged users could create
a raw socket (bnc#1152782).

CVE-2019-17056: The AF_NFC network module did not enforce CAP_NET_RAW,
which meant that unprivileged users could create a raw socket
(bsc#1152788).

CVE-2019-16413: The 9p filesystem did not protect i_size_write()
properly, which caused an i_size_read() infinite loop and denial of
service on SMP systems (bnc#1151347).

CVE-2019-15902: A backporting issue was discovered that re-introduced
the Spectre vulnerability it had aimed to eliminate. This occurred
because the backport process depends on cherry picking specific
commits, and because two (correctly ordered) code lines were swapped
(bnc#1149376).

CVE-2019-15291: Fixed a NULL pointer dereference issue that could be
caused by a malicious USB device (bnc#1146519).

CVE-2019-15807: Fixed a memory leak in the SCSI module that could be
abused to cause denial of service (bnc#1148938).

CVE-2019-13272: Fixed a mishandled the recording of the credentials of
a process that wants to create a ptrace relationship, which allowed
local users to obtain root access by leveraging certain scenarios with
a parent-child process relationship, where a parent drops privileges
and calls execve (potentially allowing control by an attacker).
(bnc#1140671).

CVE-2019-14821: An out-of-bounds access issue was fixed in the
kernel's KVM hypervisor. An unprivileged host user or process with
access to '/dev/kvm' device could use this flaw to crash the host
kernel, resulting in a denial of service or potentially escalating
privileges on the system (bnc#1151350).

CVE-2019-15505: An out-of-bounds issue had been fixed that could be
caused by crafted USB device traffic (bnc#1147122).

CVE-2017-18595: A double free in allocate_trace_buffer was fixed
(bnc#1149555).

CVE-2019-14835: A buffer overflow flaw was found in the kernel's vhost
functionality that translates virtqueue buffers to IOVs. A privileged
guest user able to pass descriptors with invalid length to the host
could use this flaw to increase their privileges on the host
(bnc#1150112).

CVE-2019-15216: A NULL pointer dereference was fixed that could be
malicious USB device (bnc#1146361).

CVE-2019-15924: A a NULL pointer dereference has been fixed in the
drivers/net/ethernet/intel/fm10k module (bnc#1149612).

CVE-2019-9456: An out-of-bounds write in the USB monitor driver has
been fixed. This issue could lead to local escalation of privilege
with System execution privileges needed. (bnc#1150025).

CVE-2019-15926: An out-of-bounds access was fixed in the
drivers/net/wireless/ath/ath6kl module. (bnc#1149527).

CVE-2019-15927: An out-of-bounds access was fixed in the
sound/usb/mixer module (bnc#1149522).

CVE-2019-15666: There was an out-of-bounds array access in the
net/xfrm module that could cause denial of service (bnc#1148394).

CVE-2017-18379: An out-of-boundary access was fixed in the
drivers/nvme/target module (bnc#1143187).

CVE-2019-15219: A NULL pointer dereference was fixed that could be
abused by a malicious USB device (bnc#1146519 1146524).

CVE-2019-15220: A use-after-free issue was fixed that could be caused
by a malicious USB device (bnc#1146519 1146526).

CVE-2019-15221: A NULL pointer dereference was fixed that could be
caused by a malicious USB device (bnc#1146519 1146529).

CVE-2019-14814: A heap-based buffer overflow was fixed in the marvell
wifi chip driver. That issue allowed local users to cause a denial of
service (system crash) or possibly execute arbitrary code
(bnc#1146512).

CVE-2019-14815: A missing length check while parsing WMM IEs was fixed
(bsc#1146512, bsc#1146514, bsc#1146516).

CVE-2019-14816: A heap-based buffer overflow in the marvell wifi chip
driver was fixed. Local users would have abused this issue to cause a
denial of service (system crash) or possibly execute arbitrary code
(bnc#1146516).

CVE-2017-18509: An issue in net/ipv6 as fixed. By setting a specific
socket option, an attacker could control a pointer in kernel land and
cause an inet_csk_listen_stop general protection fault, or potentially
execute arbitrary code under certain circumstances. The issue can be
triggered as root (e.g., inside a default LXC container or with the
CAP_NET_ADMIN capability) or after namespace unsharing. (bnc#1145477)

CVE-2019-9506: The Bluetooth BR/EDR specification used to permit
sufficiently low encryption key length and did not prevent an attacker
from influencing the key length negotiation. This allowed practical
brute-force attacks (aka 'KNOB') that could decrypt traffic and inject
arbitrary ciphertext without the victim noticing (bnc#1137865).

CVE-2019-15098: A NULL pointer dereference in drivers/net/wireless/ath
was fixed (bnc#1146378).

CVE-2019-15290: A NULL pointer dereference in
ath6kl_usb_alloc_urb_from_pipe was fixed (bsc#1146378).

CVE-2019-15239: A incorrect patch to net/ipv4 was fixed. By adding to
a write queue between disconnection and re-connection, a local
attacker could trigger multiple use-after-free conditions. This could
result in kernel crashes or potentially in privilege escalation.
(bnc#1146589)

CVE-2019-15212: A double-free issue was fixed in drivers/usb driver
(bnc#1146391).

CVE-2016-10906: A use-after-free issue was fixed in
drivers/net/ethernet/arc (bnc#1146584).

CVE-2019-15211: A use-after-free issue caused by a malicious USB
device was fixed in the drivers/media/v4l2-core driver (bnc#1146519).

CVE-2019-15217: A a NULL pointer dereference issue caused by a
malicious USB device was fixed in the drivers/media/usb/zr364xx driver
(bnc#1146519).

CVE-2019-15214: An a use-after-free issue in the sound subsystem was
fixed (bnc#1146519).

CVE-2019-15218: A NULL pointer dereference caused by a malicious USB
device was fixed in the drivers/media/usb/siano driver (bnc#1146413).

CVE-2019-15215: A use-after-free issue caused by a malicious USB
device was fixed in the drivers/media/usb/cpia2 driver (bnc#1146425).

CVE-2018-20976: A use-after-free issue was fixed in the fs/xfs driver
(bnc#1146285).

CVE-2017-18551: An out-of-bounds write was fixed in the drivers/i2c
driver (bnc#1146163).

CVE-2019-0154: An unprotected read access to i915 registers has been
fixed that could have been abused to facilitate a local
denial-of-service attack. (bsc#1135966)

CVE-2019-0155: A privilege escalation vulnerability has been fixed in
the i915 module that allowed batch buffers from user mode to gain
super user privileges. (bsc#1135967)

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1051510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1084878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1117665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1131107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1133140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1135966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1135967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1136261");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1137865");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1139073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1140671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1141013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1141054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1142458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1143187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1144123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1144903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1145477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146425");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1147022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1147122");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1148394");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1148938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149083");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149527");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1150025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1150112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1150452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1150457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1150465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1150727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1150942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1151347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1151350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1152685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1152782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1152788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1153158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1153263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1154103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1154372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1155131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1155671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-10906/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-18379/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-18509/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-18551/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-18595/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-12207/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20976/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-0154/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-0155/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-10220/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11135/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-13272/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14814/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14815/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14816/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14821/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14835/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15098/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15211/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15212/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15214/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15215/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15216/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15217/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15218/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15219/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15220/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15221/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15239/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15290/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15291/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15505/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15666/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15807/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15902/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15924/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15926/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15927/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16232/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16233/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16234/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16413/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16995/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17055/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17056/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17133/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17666/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9456/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9506/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/support/kb/doc/?id=7023735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/support/kb/doc/?id=7024251");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192949-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b73bfe19");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8:zypper in -t patch
SUSE-OpenStack-Cloud-Crowbar-8-2019-2949=1

SUSE OpenStack Cloud 8:zypper in -t patch
SUSE-OpenStack-Cloud-8-2019-2949=1

SUSE Linux Enterprise Server for SAP 12-SP3:zypper in -t patch
SUSE-SLE-SAP-12-SP3-2019-2949=1

SUSE Linux Enterprise Server 12-SP3-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-2949=1

SUSE Linux Enterprise Server 12-SP3-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-BCL-2019-2949=1

SUSE Linux Enterprise High Availability 12-SP3:zypper in -t patch
SUSE-SLE-HA-12-SP3-2019-2949=1

SUSE Enterprise Storage 5:zypper in -t patch
SUSE-Storage-5-2019-2949=1

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

HPE Helion Openstack 8:zypper in -t patch
HPE-Helion-OpenStack-8-2019-2949=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15505");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17133");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Polkit pkexec helper PTRACE_TRACEME local root exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kernel-default-kgraft-4.4.180-94.107.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"s390x", reference:"kernel-default-man-4.4.180-94.107.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"kernel-default-4.4.180-94.107.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"kernel-default-base-4.4.180-94.107.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"kernel-default-base-debuginfo-4.4.180-94.107.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"kernel-default-debuginfo-4.4.180-94.107.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"kernel-default-debugsource-4.4.180-94.107.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"kernel-default-devel-4.4.180-94.107.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"kernel-syms-4.4.180-94.107.1")) flag++;


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
