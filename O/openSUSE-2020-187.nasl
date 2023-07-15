#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-187.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(133592);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/30");

  script_cve_id("CVE-2020-1699", "CVE-2020-1700");

  script_name(english:"openSUSE Security Update : ceph (openSUSE-2020-187)");
  script_summary(english:"Check for the openSUSE-2020-187 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ceph fixes the following issues :

  - CVE-2020-1700: Fixed a denial of service against the RGW
    server via connection leakage (bsc#1161312).

  - CVE-2020-1699: Fixed a information disclosure by
    improper URL checking (bsc#1161074).

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161312"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ceph packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1699");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-dashboard-e2e");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-grafana-dashboards");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mds-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-dashboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-diskprediction-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-diskprediction-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-k8sevents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-rook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-osd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-prometheus-alerts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-radosgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-test-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cephfs-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libradospp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libradosstriper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libradosstriper1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw2-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"ceph-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-base-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-base-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-common-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-common-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-dashboard-e2e-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-debugsource-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-fuse-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-fuse-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-grafana-dashboards-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-mds-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-mds-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-mgr-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-mgr-dashboard-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-mgr-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-mgr-diskprediction-cloud-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-mgr-diskprediction-local-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-mgr-k8sevents-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-mgr-rook-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-mgr-ssh-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-mon-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-mon-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-osd-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-osd-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-prometheus-alerts-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-radosgw-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-radosgw-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-resource-agents-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-test-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-test-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ceph-test-debugsource-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cephfs-shell-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libcephfs-devel-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libcephfs2-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libcephfs2-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"librados-devel-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"librados-devel-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"librados2-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"librados2-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libradospp-devel-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libradosstriper-devel-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libradosstriper1-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libradosstriper1-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"librbd-devel-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"librbd1-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"librbd1-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"librgw-devel-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"librgw2-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"librgw2-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-ceph-argparse-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-cephfs-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-cephfs-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-rados-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-rados-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-rbd-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-rbd-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-rgw-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-rgw-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rados-objclass-devel-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rbd-fuse-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rbd-fuse-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rbd-mirror-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rbd-mirror-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rbd-nbd-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rbd-nbd-debuginfo-14.2.5.382+g8881d33957-lp151.2.10.1") ) flag++;

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
