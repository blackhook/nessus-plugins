#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1284.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124358);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-10861", "CVE-2018-1128", "CVE-2018-1129", "CVE-2018-14662", "CVE-2018-16846");

  script_name(english:"openSUSE Security Update : ceph (openSUSE-2019-1284)");
  script_summary(english:"Check for the openSUSE-2019-1284 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ceph version 13.2.4 fixes the following issues :

Security issues fixed :

  - CVE-2018-14662: Fixed an issue with LUKS 'config-key'
    safety (bsc#1111177)

  - CVE-2018-10861: Fixed an authorization bypass on OSD
    pool ops in ceph-mon (bsc#1099162)

  - CVE-2018-1128: Fixed signature check bypass in cephx
    (bsc#1096748)

  - CVE-2018-1129: Fixed replay attack in cephx protocol
    (bsc#1096748)

  - CVE-2018-16846: Enforced bounds on
    max-keys/max-uploads/max-parts in rgw (bsc#1114710)

Non-security issues fixed :

  - ceph-volume Python 3 fixes (bsc#1114567)

  - Fixed python3 module loading (bsc#1086613)

  - Fixed an issue where ceph build fails (bsc#1084645)

  - ceph's SPDK builds with march=native (bsc#1101262)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114710"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ceph packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"ceph-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-base-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-base-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-common-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-common-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-debugsource-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-fuse-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-fuse-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-mds-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-mds-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-mgr-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-mgr-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-mon-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-mon-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-osd-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-osd-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-radosgw-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-radosgw-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-resource-agents-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-test-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-test-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ceph-test-debugsource-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcephfs-devel-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcephfs2-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcephfs2-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"librados-devel-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"librados-devel-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"librados2-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"librados2-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libradosstriper-devel-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libradosstriper1-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libradosstriper1-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"librbd-devel-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"librbd1-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"librbd1-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"librgw-devel-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"librgw2-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"librgw2-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-cephfs-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-cephfs-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-rados-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-rados-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-rbd-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-rbd-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-rgw-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-rgw-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rados-objclass-devel-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rbd-fuse-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rbd-fuse-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rbd-mirror-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rbd-mirror-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rbd-nbd-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rbd-nbd-debuginfo-13.2.4.125+gad802694f5-lp150.2.3.1") ) flag++;

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
