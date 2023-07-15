#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1417-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(110123);
  script_version("1.6");
  script_cvs_date("Date: 2019/09/10 13:51:47");

  script_cve_id("CVE-2017-16818", "CVE-2018-7262");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : ceph (SUSE-SU-2018:1417-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ceph fixes the following issues: Security issues 
fixed :

  - CVE-2018-7262: rgw: malformed http headers can crash rgw
    (bsc#1081379).

  - CVE-2017-16818: User reachable asserts allow for DoS
    (bsc#1063014). Bug fixes :

  - bsc#1061461: OSDs keep generating coredumps after adding
    new OSD node to cluster.

  - bsc#1079076: RGW openssl fixes.

  - bsc#1067088: Upgrade to SES5 restarted all nodes,
    majority of OSDs aborts during start.

  - bsc#1056125: Some OSDs are down when doing performance
    testing on rbd image in EC Pool.

  - bsc#1087269: allow_ec_overwrites option not in command
    options list.

  - bsc#1051598: Fix mountpoint check for systemctl enable
    --runtime.

  - bsc#1070357: Zabbix mgr module doesn't recover from
    HEALTH_ERR.

  - bsc#1066502: After upgrading a single OSD from SES 4 to
    SES 5 the OSDs do not rejoin the cluster.

  - bsc#1067119: Crushtool decompile creates wrong device
    entries (device 20 device20) for not existing / deleted
    OSDs.

  - bsc#1060904: Loglevel misleading during keystone
    authentication.

  - bsc#1056967: Monitors goes down after pool creation on
    cluster with 120 OSDs.

  - bsc#1067705: Issues with RGW Multi-Site Federation
    between SES5 and RH Ceph Storage 2.

  - bsc#1059458: Stopping / restarting rados gateway as part
    of deepsea stage.4 executions causes core-dump of
    radosgw.

  - bsc#1087493: Commvault cannot reconnect to storage after
    restarting haproxy.

  - bsc#1066182: Container synchronization between two Ceph
    clusters failed.

  - bsc#1081600: Crash in civetweb/RGW.

  - bsc#1054061: NFS-GANESHA service failing while trying to
    list mountpoint on client.

  - bsc#1074301: OSDs keep aborting: SnapMapper failed
    asserts.

  - bsc#1086340: XFS metadata corruption on rbd-nbd mapped
    image with journaling feature enabled.

  - bsc#1080788: fsid mismatch when creating additional
    OSDs.

  - bsc#1071386: Metadata spill onto block.slow.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1063014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1067088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1067119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1067705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1079076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1080788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1081379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1081600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1087269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1087493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16818/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7262/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181417-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66713169"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-980=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-980=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-980=1

SUSE CaaS Platform ALL :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcephfs2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libradosstriper1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librbd1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librgw2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-cephfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-rados-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-rgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"ceph-common-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ceph-common-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ceph-debugsource-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libcephfs2-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libcephfs2-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librados2-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librados2-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libradosstriper1-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libradosstriper1-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librbd1-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librbd1-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librgw2-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librgw2-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-cephfs-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-cephfs-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rados-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rados-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rbd-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rbd-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rgw-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rgw-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ceph-common-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ceph-common-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ceph-debugsource-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libcephfs2-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libcephfs2-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librados2-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librados2-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libradosstriper1-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libradosstriper1-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librbd1-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librbd1-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librgw2-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librgw2-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-cephfs-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-cephfs-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-rados-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-rados-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-rbd-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-rbd-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-rgw-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-rgw-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-2.6.3")) flag++;


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
