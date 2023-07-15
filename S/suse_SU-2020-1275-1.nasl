#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1275-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(136782);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-18255",
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2018-21008",
    "CVE-2019-11091",
    "CVE-2019-14615",
    "CVE-2019-14896",
    "CVE-2019-14897",
    "CVE-2019-18675",
    "CVE-2019-19066",
    "CVE-2019-19319",
    "CVE-2019-19447",
    "CVE-2019-19767",
    "CVE-2019-19768",
    "CVE-2019-19965",
    "CVE-2019-19966",
    "CVE-2019-20054",
    "CVE-2019-20096",
    "CVE-2019-3701",
    "CVE-2019-5108",
    "CVE-2019-9455",
    "CVE-2019-9458",
    "CVE-2020-10690",
    "CVE-2020-10720",
    "CVE-2020-10942",
    "CVE-2020-11494",
    "CVE-2020-11608",
    "CVE-2020-11609",
    "CVE-2020-2732",
    "CVE-2020-8647",
    "CVE-2020-8648",
    "CVE-2020-8649",
    "CVE-2020-8992",
    "CVE-2020-9383"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2020:1275-1) (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The SUSE Linux Enterprise 12 SP3 kernel was updated to receive various
security and bugfixes.

The following security bugs were fixed :

CVE-2020-11494: An issue was discovered in slc_bump in
drivers/net/can/slcan.c, which allowed attackers to read uninitialized
can_frame data, potentially containing sensitive information from
kernel stack memory, if the configuration lacks CONFIG_INIT_STACK_ALL
(bnc#1168424).

CVE-2020-10942: In get_raw_socket in drivers/vhost/net.c lacks
validation of an sk_family field, which might allow attackers to
trigger kernel stack corruption via crafted system calls
(bnc#1167629).

CVE-2020-8647: Fixed a use-after-free vulnerability in the
vc_do_resize function in drivers/tty/vt/vt.c (bnc#1162929).

CVE-2020-8649: Fixed a use-after-free vulnerability in the
vgacon_invert_region function in drivers/video/console/vgacon.c
(bnc#1162931).

CVE-2020-9383: Fixed an issue in set_fdc in drivers/block/floppy.c,
which leads to a wait_til_ready out-of-bounds read (bnc#1165111).

CVE-2019-9458: In the video driver there was a use after free due to a
race condition. This could lead to local escalation of privilege with
no additional execution privileges needed (bnc#1168295).

CVE-2019-3701: Fixed an issue in can_can_gw_rcv, which could cause a
system crash (bnc#1120386).

CVE-2019-19768: Fixed a use-after-free in the __blk_add_trace function
in kernel/trace/blktrace.c (bnc#1159285).

CVE-2020-11609: Fixed a NULL pointer dereference in the stv06xx
subsystem caused by mishandling invalid descriptors (bnc#1168854).

CVE-2020-10720: Fixed a use-after-free read in napi_gro_frags()
(bsc#1170778).

CVE-2020-10690: Fixed the race between the release of ptp_clock and
cdev (bsc#1170056).

CVE-2019-9455: Fixed a pointer leak due to a WARN_ON statement in a
video driver. This could lead to local information disclosure with
System execution privileges needed (bnc#1170345).

CVE-2020-11608: Fixed an issue in drivers/media/usb/gspca/ov519.c
caused by a NULL pointer dereferences in ov511_mode_init_regs and
ov518_mode_init_regs when there are zero endpoints (bnc#1168829).

CVE-2017-18255: The perf_cpu_time_max_percent_handler function in
kernel/events/core.c allowed local users to cause a denial of service
(integer overflow) or possibly have unspecified other impact via a
large value, as demonstrated by an incorrect sample-rate calculation
(bnc#1087813).

CVE-2020-8648: There was a use-after-free vulnerability in the
n_tty_receive_buf_common function in drivers/tty/n_tty.c
(bnc#1162928).

CVE-2020-2732: A flaw was discovered in the way that the KVM
hypervisor handled instruction emulation for an L2 guest when nested
virtualisation is enabled. Under some circumstances, an L2 guest may
trick the L0 guest into accessing sensitive L1 resources that should
be inaccessible to the L2 guest (bnc#1163971).

CVE-2019-5108: Fixed a denial-of-service vulnerability caused by
triggering AP to send IAPP location updates for stations before the
required authentication process has completed (bnc#1159912).

CVE-2020-8992: ext4_protect_reserved_inode in fs/ext4/block_validity.c
allowed attackers to cause a denial of service (soft lockup) via a
crafted journal size (bnc#1164069).

CVE-2018-21008: Fixed a use-after-free which could be caused by the
function rsi_mac80211_detach in the file
drivers/net/wireless/rsi/rsi_91x_mac80211.c (bnc#1149591).

CVE-2019-14896: A heap-based buffer overflow vulnerability was found
in Marvell WiFi chip driver. A remote attacker could cause a denial of
service (system crash) or, possibly execute arbitrary code, when the
lbs_ibss_join_existing function is called after a STA connects to an
AP (bnc#1157157).

CVE-2019-14897: A stack-based buffer overflow was found in Marvell
WiFi chip driver. An attacker is able to cause a denial of service
(system crash) or, possibly execute arbitrary code, when a STA works
in IBSS mode (allows connecting stations together without the use of
an AP) and connects to another STA (bnc#1157155).

CVE-2019-18675: Fixed an integer overflow in cpia2_remap_buffer in
drivers/media/usb/cpia2/cpia2_core.c because cpia2 has its own mmap
implementation. This allowed local users (with /dev/video0 access) to
obtain read and write permissions on kernel physical pages, which can
possibly result in a privilege escalation (bnc#1157804).

CVE-2019-14615: Insufficient control flow in certain data structures
for some Intel(R) Processors with Intel(R) Processor Graphics may have
allowed an unauthenticated user to potentially enable information
disclosure via local access (bnc#1160195, bsc#1165881).

CVE-2019-19965: Fixed a NULL pointer dereference in
drivers/scsi/libsas/sas_discover.c because of mishandling of port
disconnection during discovery, related to a PHY down race condition
(bnc#1159911).

CVE-2019-20054: Fixed a NULL pointer dereference in
drop_sysctl_table() in fs/proc/proc_sysctl.c, related to put_links
(bnc#1159910).

CVE-2019-20096: Fixed a memory leak in __feat_register_sp() in
net/dccp/feat.c, which may cause denial of service (bnc#1159908).

CVE-2019-19966: Fixed a use-after-free in cpia2_exit() in
drivers/media/usb/cpia2/cpia2_v4l.c that will cause denial of service
(bnc#1159841).

CVE-2019-19447: Fixed an issue with mounting a crafted ext4 filesystem
image, performing some operations, and unmounting could lead to a
use-after-free in ext4_put_super in fs/ext4/super.c, related to
dump_orphan_list in fs/ext4/super.c (bnc#1158819).

CVE-2019-19319: Fixed an issue with a setxattr operation, after a
mount of a crafted ext4 image, can cause a slab-out-of-bounds write
access because of an ext4_xattr_set_entry use-after-free in
fs/ext4/xattr.c when a large old_size value is used in a memset call
(bnc#1158021).

CVE-2019-19767: Fixed mishandling of ext4_expand_extra_isize, as
demonstrated by use-after-free errors in __ext4_expand_extra_isize and
ext4_xattr_set_entry, related to fs/ext4/inode.c and fs/ext4/super.c
(bnc#1159297).

CVE-2019-11091,CVE-2018-12126,CVE-2018-12130,CVE-2018-12127: Earlier
mitigations for the 'MDS' Microarchitectural Data Sampling attacks
were not complete. An additional fix was added to the x86_64 fast
systemcall path to further mitigate these attacks. (bsc#1164846
bsc#1170847)

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1056134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1087813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1120386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1133147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1137325");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1145929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1154118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1154844");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1155689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1157155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1157157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1157303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1157804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159910");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1160195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1161586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1163508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1163971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1164009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1164051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1164069");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1164078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1164846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1165111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1165311");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1165873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1165881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1165984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1165985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1167421");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1167423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1167629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1168075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1168295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1168424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1168829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1168854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-18255/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-12126/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-12127/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-12130/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-21008/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11091/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14615/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14896/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14897/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18675/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19066/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19319/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19447/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19767/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19768/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19965/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19966/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20054/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20096/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3701/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-5108/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9455/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9458/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10690/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10720/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10942/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11494/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11608/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11609/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2732/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8647/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8648/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8649/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8992/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-9383/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201275-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44158709");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-8-2020-1275=1

SUSE OpenStack Cloud 8 :

zypper in -t patch SUSE-OpenStack-Cloud-8-2020-1275=1

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2020-1275=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2020-1275=1

SUSE Linux Enterprise Server 12-SP3-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-BCL-2020-1275=1

SUSE Linux Enterprise High Availability 12-SP3 :

zypper in -t patch SUSE-SLE-HA-12-SP3-2020-1275=1

SUSE Enterprise Storage 5 :

zypper in -t patch SUSE-Storage-5-2020-1275=1

HPE Helion Openstack 8 :

zypper in -t patch HPE-Helion-OpenStack-8-2020-1275=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/22");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_116-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_116-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kernel-default-kgraft-4.4.180-94.116.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_116-default-1-4.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_116-default-debuginfo-1-4.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"s390x", reference:"kernel-default-man-4.4.180-94.116.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"kernel-default-4.4.180-94.116.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"kernel-default-base-4.4.180-94.116.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"kernel-default-base-debuginfo-4.4.180-94.116.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"kernel-default-debuginfo-4.4.180-94.116.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"kernel-default-debugsource-4.4.180-94.116.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"kernel-default-devel-4.4.180-94.116.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"kernel-syms-4.4.180-94.116.1")) flag++;


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
