#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1573-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149462);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2020-0433",
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-25672",
    "CVE-2020-25673",
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
    "CVE-2021-20219",
    "CVE-2021-26931",
    "CVE-2021-27363",
    "CVE-2021-27364",
    "CVE-2021-27365",
    "CVE-2021-28038",
    "CVE-2021-28660",
    "CVE-2021-28688",
    "CVE-2021-28950",
    "CVE-2021-28964",
    "CVE-2021-28971",
    "CVE-2021-28972",
    "CVE-2021-29154",
    "CVE-2021-29155",
    "CVE-2021-29264",
    "CVE-2021-29265",
    "CVE-2021-29647",
    "CVE-2021-29650",
    "CVE-2021-30002"
  );

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2021:1573-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The SUSE Linux Enterprise 15 kernel was updated to receive various
security and bugfixes.

The following security bugs were fixed :

CVE-2020-36312: Fixed an issue in virt/kvm/kvm_main.c that had a
kvm_io_bus_unregister_dev memory leak upon a kmalloc failure
(bnc#1184509).

CVE-2021-29650: Fixed an issue inside the netfilter subsystem that
allowed attackers to cause a denial of service (panic) because
net/netfilter/x_tables.c and include/linux/netfilter/x_tables.h lack a
full memory barrier upon the assignment of a new table value
(bnc#1184208).

CVE-2021-29155: Fixed an issue within kernel/bpf/verifier.c that
performed undesirable out-of-bounds speculation on pointer arithmetic,
leading to side-channel attacks that defeat Spectre mitigations and
obtain sensitive information from kernel memory. Specifically, for
sequences of pointer arithmetic operations, the pointer modification
performed by the first operation is not correctly accounted for when
restricting subsequent operations (bnc#1184942).

CVE-2020-36310: Fixed an issue in arch/x86/kvm/svm/svm.c that allowed
a set_memory_region_test infinite loop for certain nested page faults
(bnc#1184512).

CVE-2020-27673: Fixed an issue in Xen where a guest OS users could
have caused a denial of service (host OS hang) via a high rate of
events to dom0 (bnc#1177411, bnc#1184583).

CVE-2021-29154: Fixed BPF JIT compilers that allowed to execute
arbitrary code within the kernel context (bnc#1184391).

CVE-2020-25673: Fixed NFC endless loops caused by repeated
llcp_sock_connect() (bsc#1178181).

CVE-2020-25672: Fixed NFC memory leak in llcp_sock_connect()
(bsc#1178181).

CVE-2020-25671: Fixed NFC refcount leak in llcp_sock_connect()
(bsc#1178181).

CVE-2020-25670: Fixed NFC refcount leak in llcp_sock_bind()
(bsc#1178181).

CVE-2020-36311: Fixed an issue in arch/x86/kvm/svm/sev.c that allowed
attackers to cause a denial of service (soft lockup) by triggering
destruction of a large SEV VM (which requires unregistering many
encrypted regions) (bnc#1184511).

CVE-2021-28950: Fixed an issue in fs/fuse/fuse_i.h where a 'stall on
CPU' could have occured because a retry loop continually finds the
same bad inode (bnc#1184194, bnc#1184211).

CVE-2020-36322: Fixed an issue inside the FUSE filesystem
implementation where fuse_do_getattr() calls make_bad_inode() in
inappropriate situations, could have caused a system crash. NOTE: the
original fix for this vulnerability was incomplete, and its
incompleteness is tracked as CVE-2021-28950 (bnc#1184211).

CVE-2021-30002: Fixed a memory leak issue when a webcam device exists
(bnc#1184120).

CVE-2021-3483: Fixed a use-after-free bug in nosy_ioctl()
(bsc#1184393).

CVE-2021-20219: Fixed a denial of service vulnerability in
drivers/tty/n_tty.c of the Linux kernel. In this flaw a local attacker
with a normal user privilege could have delayed the loop and cause a
threat to the system availability (bnc#1184397).

CVE-2021-28964: Fixed a race condition in fs/btrfs/ctree.c that could
have caused a denial of service because of a lack of locking on an
extent buffer before a cloning operation (bnc#1184193).

CVE-2021-3444: Fixed the bpf verifier as it did not properly handle
mod32 destination register truncation when the source register was
known to be 0. A local attacker with the ability to load bpf programs
could use this gain out-of-bounds reads in kernel memory leading to
information disclosure (kernel memory), and possibly out-of-bounds
writes that could potentially lead to code execution (bnc#1184170).

CVE-2021-28971: Fixed a potential local denial of service in
intel_pmu_drain_pebs_nhm where userspace applications can cause a
system crash because the PEBS status in a PEBS record is mishandled
(bnc#1184196).

CVE-2021-28688: Fixed XSA-365 that includes initialization of pointers
such that subsequent cleanup code wouldn't use uninitialized or stale
values. This initialization went too far and may under certain
conditions also overwrite pointers which are in need of cleaning up.
The lack of cleanup would result in leaking persistent grants. The
leak in turn would prevent fully cleaning up after a respective guest
has died, leaving around zombie domains (bnc#1183646).

CVE-2021-29265: Fixed an issue in usbip_sockfd_store in
drivers/usb/usbip/stub_dev.c that allowed attackers to cause a denial
of service (GPF) because the stub-up sequence has race conditions
during an update of the local and shared status (bnc#1184167).

CVE-2021-29264: Fixed an issue in
drivers/net/ethernet/freescale/gianfar.c in the Freescale Gianfar
Ethernet driver that allowed attackers to cause a system crash because
a negative fragment size is calculated in situations involving an rx
queue overrun when jumbo packets are used and NAPI is enabled
(bnc#1184168).

CVE-2021-28972: Fixed an issue in drivers/pci/hotplug/rpadlpar_sysfs.c
where the RPA PCI Hotplug driver had a user-tolerable buffer overflow
when writing a new device name to the driver from userspace, allowing
userspace to write data to the kernel stack frame directly. This
occurs because add_slot_store and remove_slot_store mishandle drc_name
'\0' termination (bnc#1184198).

CVE-2021-29647: Fixed an issue in kernel qrtr_recvmsg in
net/qrtr/qrtr.c that allowed attackers to obtain sensitive information
from kernel memory because of a partially uninitialized data structure
(bnc#1184192).

CVE-2020-27171: Fixed an issue in kernel/bpf/verifier.c that had an
off-by-one error (with a resultant integer underflow) affecting
out-of-bounds speculation on pointer arithmetic, leading to
side-channel attacks that defeat Spectre mitigations and obtain
sensitive information from kernel memory (bnc#1183686, bnc#1183775).

CVE-2020-27170: Fixed an issue in kernel/bpf/verifier.c that performed
undesirable out-of-bounds speculation on pointer arithmetic, leading
to side-channel attacks that defeat Spectre mitigations and obtain
sensitive information from kernel memory. This affects pointer types
that do not define a ptr_limit (bnc#1183686 bnc#1183775).

CVE-2021-28660: Fixed rtw_wx_set_scan in
drivers/staging/rtl8188eu/os_dep/ioctl_linux.c that allowed writing
beyond the end of the ssid array (bnc#1183593).

CVE-2020-35519: Update patch reference for x25 fix (bsc#1183696).

CVE-2021-3428: Fixed ext4 integer overflow in ext4_es_cache_extent
(bsc#1173485, bsc#1183509).

CVE-2020-0433: Fixed blk_mq_queue_tag_busy_iter of blk-mq-tag.c, where
a possible use after free due to improper locking could have happened.
This could have led to local escalation of privilege with no
additional execution privileges needed. User interaction is not needed
for exploitation (bnc#1176720).

CVE-2021-28038: Fixed an issue with Xen PV. A certain part of the
netback driver lacks necessary treatment of errors such as failed
memory allocations (as a result of changes to the handling of grant
mapping errors). A host OS denial of service may occur during
misbehavior of a networking frontend driver. NOTE: this issue exists
because of an incomplete fix for CVE-2021-26931 (bnc#1183022,
bnc#1183069).

CVE-2020-27815: Fixed jfs array index bounds check in dbAdjTree
(bsc#1179454).

CVE-2021-27365: Fixed an issue inside the iSCSI data structures that
does not have appropriate length constraints or checks, and can exceed
the PAGE_SIZE value. An unprivileged user can send a Netlink message
that is associated with iSCSI, and has a length up to the maximum
length of a Netlink message (bnc#1182715).

CVE-2021-27363: Fixed an issue with a kernel pointer leak that could
have been used to determine the address of the iscsi_transport
structure. When an iSCSI transport is registered with the iSCSI
subsystem, the transport's handle is available to unprivileged users
via the sysfs file system, at
/sys/class/iscsi_transport/$TRANSPORT_NAME/handle. When read, the
show_transport_handle function (in
drivers/scsi/scsi_transport_iscsi.c) is called, which leaks the
handle. This handle is actually the pointer to an iscsi_transport
struct in the kernel module's global variables (bnc#1182716).

CVE-2021-27364: Fixed an issue in drivers/scsi/scsi_transport_iscsi.c
where an unprivileged user can craft Netlink messages (bnc#1182717).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1047233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183069");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184196");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184397");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1185113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1185244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1185248");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-0433/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25670/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25671/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25672/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25673/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27170/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27171/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27673/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27815/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35519/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36310/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36311/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36312/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36322/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20219/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27363/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27364/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27365/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28038/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28660/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28688/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28950/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28964/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28971/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28972/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29154/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29155/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29264/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29265/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29647/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29650/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30002/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3428/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3444/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3483/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211573-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78e5e7d1");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2021-1573=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2021-1573=1

SUSE Linux Enterprise Module for Live Patching 15 :

zypper in -t patch SUSE-SLE-Module-Live-Patching-15-2021-1573=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-1573=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-1573=1

SUSE Linux Enterprise High Availability 15 :

zypper in -t patch SUSE-SLE-Product-HA-15-2021-1573=1");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "s390x") audit(AUDIT_ARCH_NOT, "s390x", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-base-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-debuginfo-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-debugsource-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-devel-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-devel-debuginfo-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-man-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-obs-build-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-obs-build-debugsource-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-syms-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-vanilla-base-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-vanilla-base-debuginfo-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-vanilla-debuginfo-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-vanilla-debugsource-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-debugsource-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"reiserfs-kmp-default-4.12.14-150.72.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"reiserfs-kmp-default-debuginfo-4.12.14-150.72.1")) flag++;


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
