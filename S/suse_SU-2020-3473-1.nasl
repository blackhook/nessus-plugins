#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3473-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(143700);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2020-25660");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ceph (SUSE-SU-2020:3473-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ceph fixes the following issues :

CVE-2020-25660: Bring back CEPHX_V2 authorizer challenges
(bsc#1177843).

Added --container-init feature (bsc#1177319, bsc#1163764)

Made journald as the logdriver again (bsc#1177933)

Fixes a condition check for copy_tree, copy_files, and move_files in
cephadm (bsc#1177676)

Fixed a bug where device_health_metrics pool gets created even without
any OSDs in the cluster (bsc#1173079)

Log cephadm output /var/log/ceph/cephadm.log (bsc#1174644)

Fixed a bug where the orchestrator didn't come up anymore after the
deletion of OSDs (bsc#1176499)

Fixed a bug where cephadm fails to deploy all OSDs and gets stuck
(bsc#1177450)

python-common will no longer skip unavailable disks (bsc#1177151)

Added snap-schedule module (jsc#SES-704)

Updated the SES7 downstream branding (bsc#1175120, bsc#1175161,
bsc#1175169, bsc#1170498)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1163764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1170200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1170498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1173079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1175120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1175161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1175169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1176451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1176499"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1176638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25660/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203473-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc1721ab"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2020-3473=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-debugsource");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-cephfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rados-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rados-objclass-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-nbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-nbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", reference:"ceph-common-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"ceph-common-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"ceph-debugsource-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libcephfs-devel-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libcephfs2-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libcephfs2-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librados-devel-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librados-devel-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librados2-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librados2-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libradospp-devel-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librbd-devel-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librbd1-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librbd1-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librgw-devel-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librgw2-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librgw2-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-ceph-argparse-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-ceph-common-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-cephfs-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-cephfs-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-rados-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-rados-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-rbd-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-rbd-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-rgw-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-rgw-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"rados-objclass-devel-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"rbd-nbd-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"rbd-nbd-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"ceph-common-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"ceph-common-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"ceph-debugsource-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libcephfs-devel-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libcephfs2-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libcephfs2-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librados-devel-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librados-devel-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librados2-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librados2-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libradospp-devel-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librbd-devel-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librbd1-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librbd1-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librgw-devel-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librgw2-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librgw2-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-ceph-argparse-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-ceph-common-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-cephfs-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-cephfs-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-rados-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-rados-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-rbd-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-rbd-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-rgw-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-rgw-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"rados-objclass-devel-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"rbd-nbd-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"rbd-nbd-debuginfo-15.2.5.667+g1a579d5bf2-3.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ceph");
}
