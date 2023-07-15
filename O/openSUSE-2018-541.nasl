#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-541.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110257);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-16818", "CVE-2018-7262");

  script_name(english:"openSUSE Security Update : ceph (openSUSE-2018-541)");
  script_summary(english:"Check for the openSUSE-2018-541 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ceph fixes the following issues :

Security issues fixed :

  - CVE-2018-7262: rgw: malformed http headers can crash rgw
    (bsc#1081379).

  - CVE-2017-16818: User reachable asserts allow for DoS
    (bsc#1063014).

Bug fixes :

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

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087493"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ceph packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mds-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-osd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-radosgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-test-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libradosstriper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libradosstriper1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-ceph-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-cephfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rados-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-cephfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rados-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rados-objclass-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-mirror-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-nbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-nbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"ceph-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-base-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-base-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-common-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-common-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-debugsource-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-fuse-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-fuse-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-mds-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-mds-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-mgr-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-mgr-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-mon-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-mon-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-osd-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-osd-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-radosgw-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-radosgw-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-resource-agents-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-test-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-test-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-test-debugsource-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libcephfs-devel-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libcephfs2-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libcephfs2-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librados-devel-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librados-devel-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librados2-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librados2-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libradosstriper-devel-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libradosstriper1-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libradosstriper1-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librbd-devel-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librbd1-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librbd1-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librgw-devel-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librgw2-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librgw2-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-ceph-compat-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-cephfs-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-cephfs-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-rados-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-rados-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-rbd-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-rbd-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-rgw-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-rgw-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-ceph-argparse-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-cephfs-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-cephfs-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-rados-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-rados-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-rbd-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-rbd-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-rgw-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-rgw-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rados-objclass-devel-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rbd-fuse-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rbd-fuse-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rbd-mirror-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rbd-mirror-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rbd-nbd-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rbd-nbd-debuginfo-12.2.5+git.1524775272.5e7ea8cf03-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ceph-test / ceph-test-debuginfo / ceph-test-debugsource / ceph / etc");
}
