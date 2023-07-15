#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2327.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145323);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2020-27781");

  script_name(english:"openSUSE Security Update : ceph (openSUSE-2020-2327)");
  script_summary(english:"Check for the openSUSE-2020-2327 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ceph fixes the following issues :

Security issue fixed :

  - CVE-2020-27781: Fixed a privilege escalation via the
    ceph_volume_client Python interface (bsc#1180155,
    bsc#1179802).

Non-security issues fixed :

  - Update to 15.2.8-80-g1f4b6229ca :

  + Rebase on tip of upstream 'octopus' branch, SHA1
    bdf3eebcd22d7d0b3dd4d5501bee5bac354d5b55

  - upstream Octopus v15.2.8 release, see
    https://ceph.io/releases/v15-2-8-octopus-released/

  - Update to 15.2.7-776-g343cd10fe5 :

  + Rebase on tip of upstream 'octopus' branch, SHA1
    1b8a634fdcd94dfb3ba650793fb1b6d09af65e05

  - (bsc#1178860) mgr/dashboard: Disable TLS 1.0 and 1.1

  + (bsc#1179016) rpm: require smartmontools on SUSE

  + (bsc#1180107) ceph-volume: pass --filter-for-batch from
    drive-group subcommand

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ceph.io/releases/v15-2-8-octopus-released/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ceph packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-grafana-dashboards");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-immutable-object-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-immutable-object-cache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mds-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-dashboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-diskprediction-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-diskprediction-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-k8sevents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-rook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-osd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-prometheus-alerts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-radosgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-test-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cephfs-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libradospp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ceph-common");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"ceph-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-base-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-base-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-common-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-common-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-debugsource-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-fuse-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-fuse-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-grafana-dashboards-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-immutable-object-cache-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-immutable-object-cache-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-mds-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-mds-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-mgr-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-mgr-cephadm-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-mgr-dashboard-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-mgr-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-mgr-diskprediction-cloud-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-mgr-diskprediction-local-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-mgr-k8sevents-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-mgr-modules-core-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-mgr-rook-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-mon-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-mon-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-osd-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-osd-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-prometheus-alerts-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-radosgw-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-radosgw-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-test-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-test-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ceph-test-debugsource-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cephadm-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cephfs-shell-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libcephfs-devel-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libcephfs2-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libcephfs2-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librados-devel-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librados-devel-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librados2-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librados2-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libradospp-devel-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librbd-devel-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librbd1-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librbd1-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librgw-devel-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librgw2-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librgw2-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-ceph-argparse-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-ceph-common-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-cephfs-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-cephfs-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-rados-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-rados-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-rbd-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-rbd-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-rgw-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-rgw-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rados-objclass-devel-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rbd-fuse-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rbd-fuse-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rbd-mirror-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rbd-mirror-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rbd-nbd-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rbd-nbd-debuginfo-15.2.8.80+g1f4b6229ca-lp152.2.9.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ceph-test / ceph-test-debuginfo / ceph-test-debugsource / ceph / etc");
}
