#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0586-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(122809);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-10861", "CVE-2018-1128", "CVE-2018-1129", "CVE-2018-14662", "CVE-2018-16846");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ceph (SUSE-SU-2019:0586-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ceph version 13.2.4 fixes the following issues :

Security issues fixed :

CVE-2018-14662: Fixed an issue with LUKS 'config-key' safety
(bsc#1111177)

CVE-2018-10861: Fixed an authorization bypass on OSD pool ops in
ceph-mon (bsc#1099162)

CVE-2018-1128: Fixed signature check bypass in cephx (bsc#1096748)

CVE-2018-1129: Fixed replay attack in cephx protocol (bsc#1096748)

CVE-2018-16846: Enforced bounds on max-keys/max-uploads/max-parts in
rgw

Non-security issues fixed: ceph-volume Python 3 fixes (bsc#1114567)

fix python3 module loading (bsc#1086613)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1084645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1096748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1099162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1114567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10861/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1128/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1129/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14662/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16846/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190586-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3125034"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-586=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-586=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcephfs2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libradosstriper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libradosstriper1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librbd1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librgw2-debuginfo");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/13");
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
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-base-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-base-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-common-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-common-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-debugsource-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-fuse-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-fuse-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-mds-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-mds-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-mgr-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-mgr-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-mon-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-mon-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-osd-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-osd-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-radosgw-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-radosgw-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ceph-resource-agents-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcephfs-devel-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcephfs2-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcephfs2-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"librados-devel-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"librados-devel-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"librados2-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"librados2-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libradosstriper-devel-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libradosstriper1-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libradosstriper1-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"librbd-devel-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"librbd1-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"librbd1-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"librgw-devel-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"librgw2-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"librgw2-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-cephfs-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-cephfs-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-rados-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-rados-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-rbd-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-rbd-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-rgw-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-rgw-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rados-objclass-devel-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rbd-fuse-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rbd-fuse-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rbd-mirror-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rbd-mirror-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rbd-nbd-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rbd-nbd-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-base-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-base-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-common-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-common-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-debugsource-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-fuse-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-fuse-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-mds-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-mds-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-mgr-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-mgr-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-mon-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-mon-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-osd-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-osd-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-radosgw-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-radosgw-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ceph-resource-agents-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcephfs-devel-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcephfs2-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcephfs2-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"librados-devel-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"librados-devel-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"librados2-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"librados2-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libradosstriper-devel-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libradosstriper1-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libradosstriper1-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"librbd-devel-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"librbd1-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"librbd1-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"librgw-devel-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"librgw2-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"librgw2-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-cephfs-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-cephfs-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-rados-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-rados-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-rbd-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-rbd-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-rgw-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-rgw-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rados-objclass-devel-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rbd-fuse-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rbd-fuse-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rbd-mirror-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rbd-mirror-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rbd-nbd-13.2.4.125+gad802694f5-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rbd-nbd-debuginfo-13.2.4.125+gad802694f5-3.7.2")) flag++;


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
