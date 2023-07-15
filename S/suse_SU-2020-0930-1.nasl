#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0930-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(135268);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-1759", "CVE-2020-1760");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ceph (SUSE-SU-2020:0930-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ceph fixes the following issues :

CVE-2020-1759: Fixed once reuse in msgr V2 secure mode (bsc#1166403)

CVE-2020-1760: Fixed XSS due to RGW GetObject header-splitting
(bsc#1166484).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1166403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1166484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-1759/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-1760/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200930-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc4ef264"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-930=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2020-930=1

SUSE Enterprise Storage 6:zypper in -t patch SUSE-Storage-6-2020-930=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1759");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"ceph-test-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"ceph-test-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"ceph-test-debugsource-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-base-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-base-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-common-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-common-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-debugsource-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-fuse-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-fuse-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mds-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mds-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mgr-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mgr-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mon-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mon-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-osd-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-osd-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-radosgw-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-radosgw-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cephfs-shell-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcephfs-devel-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcephfs2-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcephfs2-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librados-devel-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librados-devel-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librados2-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librados2-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libradospp-devel-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librbd-devel-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librbd1-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librbd1-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librgw-devel-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librgw2-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librgw2-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-ceph-argparse-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-cephfs-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-cephfs-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rados-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rados-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rbd-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rbd-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rgw-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rgw-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rados-objclass-devel-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-fuse-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-fuse-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-mirror-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-mirror-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-nbd-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-nbd-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"ceph-test-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"ceph-test-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"ceph-test-debugsource-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-base-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-base-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-common-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-common-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-debugsource-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-fuse-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-fuse-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mds-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mds-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mgr-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mgr-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mon-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mon-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-osd-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-osd-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-radosgw-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-radosgw-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cephfs-shell-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcephfs-devel-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcephfs2-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcephfs2-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librados-devel-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librados-devel-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librados2-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librados2-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libradospp-devel-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librbd-devel-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librbd1-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librbd1-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librgw-devel-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librgw2-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librgw2-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-ceph-argparse-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-cephfs-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-cephfs-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rados-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rados-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rbd-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rbd-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rgw-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rgw-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rados-objclass-devel-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-fuse-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-fuse-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-mirror-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-mirror-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-nbd-14.2.5.389+gb0f23ac248-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-nbd-debuginfo-14.2.5.389+gb0f23ac248-3.35.2")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
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
