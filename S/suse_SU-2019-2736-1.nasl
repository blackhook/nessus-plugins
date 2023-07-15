#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2736-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(130161);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-10222");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ceph, ceph-iscsi, ses-manual_en (SUSE-SU-2019:2736-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ceph, ceph-iscsi and ses-manual_en fixes the following
issues :

Security issues fixed :

CVE-2019-10222: Fixed RGW crash caused by unauthenticated clients.
(bsc#1145093)

Non-security issues-fixed: ceph-volume: prints errors to stdout with
--format json (bsc#1132767)

mgr/dashboard: Changing rgw-api-host does not get effective without
disable/enable dashboard mgr module (bsc#1137503)

mgr/dashboard: Silence Alertmanager alerts (bsc#1141174)

mgr/dashboard: Fix e2e failures caused by webdriver version
(bsc#1145759)

librbd: always try to acquire exclusive lock when removing image
(bsc#1149093)

The no{up,down,in,out} related commands have been revamped
(bsc#1151990)

radosgw-admin gets two new subcommands for managing expire-stale
objects. (bsc#1151991)

Deploying a single new BlueStore OSD on a cluster upgraded to SES6
from SES5 breaks pool utilization stats reported by ceph df
(bsc#1151992)

Ceph cluster will no longer issue a health warning if CRUSH tunables
are older than 'hammer' (bsc#1151993)

Nautilus-based librbd clients can not open images on Jewel clusters
(bsc#1151994)

The RGW num_rados_handles has been removed in Ceph 14.2.3
(bsc#1151995)

'osd_deep_scrub_large_omap_object_key_threshold' has been lowered in
Nautilus 14.2.3 (bsc#1152002)

Support iSCSI target-level CHAP authentication (bsc#1145617)

Validation and render of iSCSI controls based 'type' (bsc#1140491)

Fix error editing iSCSI image advanced settings (bsc#1146656)

Fix error during iSCSI target edit

Fixes in ses-manual_en: Added a new chapter with changelogs of Ceph
releases. (bsc#1135584)

Rewrote rolling updates and replaced running stage.0 with manual
commands to prevent infinite loop. (bsc#1134444)

Improved name of CaaSP to its fuller version. (bsc#1151439)

Verify which OSD's are going to be removed before running stage.5.
(bsc#1150406)

Added two additional steps to recovering an OSD. (bsc#1147132)

Fixes in ceph-iscsi: Validate kernel LIO controls type and value
(bsc#1140491)

TPG lun_id persistence (bsc#1145618)

Target level CHAP authentication (bsc#1145617)

ceph-iscsi was updated to the upstream 3.2 release: Always use host
FQDN instead of shortname

Validate min/max value for target controls and rbd:user/tcmu-runner
image controls (bsc#1140491)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1132767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1134444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1137503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1141174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1145093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1145617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1145618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1145759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1146656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1147132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1149093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1150406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1151439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1151990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1151991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1151992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1151993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1151994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1151995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1152002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10222/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192736-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd6b95a4"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2736=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-2736=1

SUSE Enterprise Storage 6:zypper in -t patch
SUSE-Storage-6-2019-2736=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-mds-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-mgr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-mon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-osd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-radosgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-test-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cephfs-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcephfs2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libradospp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librbd1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librgw2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-cephfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rados-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rados-objclass-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-mirror-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-nbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-nbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/23");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"ceph-test-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"ceph-test-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"ceph-test-debugsource-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-base-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-base-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-common-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-common-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-debugsource-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-fuse-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-fuse-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mds-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mds-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mgr-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mgr-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mon-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mon-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-osd-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-osd-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-radosgw-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-radosgw-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cephfs-shell-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcephfs-devel-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcephfs2-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcephfs2-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librados-devel-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librados-devel-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librados2-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librados2-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libradospp-devel-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librbd-devel-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librbd1-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librbd1-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librgw-devel-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librgw2-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librgw2-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-ceph-argparse-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-cephfs-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-cephfs-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rados-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rados-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rbd-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rbd-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rgw-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rgw-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rados-objclass-devel-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-fuse-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-fuse-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-mirror-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-mirror-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-nbd-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-nbd-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"ceph-test-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"ceph-test-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"ceph-test-debugsource-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-base-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-base-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-common-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-common-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-debugsource-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-fuse-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-fuse-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mds-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mds-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mgr-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mgr-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mon-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mon-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-osd-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-osd-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-radosgw-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-radosgw-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cephfs-shell-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcephfs-devel-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcephfs2-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcephfs2-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librados-devel-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librados-devel-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librados2-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librados2-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libradospp-devel-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librbd-devel-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librbd1-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librbd1-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librgw-devel-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librgw2-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librgw2-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-ceph-argparse-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-cephfs-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-cephfs-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rados-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rados-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rbd-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rbd-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rgw-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rgw-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rados-objclass-devel-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-fuse-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-fuse-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-mirror-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-mirror-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-nbd-14.2.4.373+gc3e67ed133-3.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-nbd-debuginfo-14.2.4.373+gc3e67ed133-3.19.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ceph / ceph-iscsi / ses-manual_en");
}
