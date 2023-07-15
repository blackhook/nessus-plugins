#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0499-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(122476);
  script_version("1.3");
  script_cvs_date("Date: 2020/02/07");

  script_cve_id("CVE-2018-14662", "CVE-2018-16846", "CVE-2018-16889");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : ceph (SUSE-SU-2019:0499-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ceph fixes the following issues :

Security issues fixed :

CVE-2018-14662: mon: limit caps allowed to access the config store
(bsc#1111177)

CVE-2018-16846: rgw: enforce bounds on max-keys/max-uploads/max-parts
(bsc#1114710)

CVE-2018-16889: rgw: sanitize customer encryption keys from log output
in v4 auth (bsc#1121567)

Non-security issue fixed: os/bluestore: avoid frequent allocator dump
on bluefs rebalance failure (bsc#1113246)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113246"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1114710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14662/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16846/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16889/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190499-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b59d5e0c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-499=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2019-499=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-499=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-499=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-499=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2019-499=1

SUSE Enterprise Storage 5:zypper in -t patch SUSE-Storage-5-2019-499=1

SUSE CaaS Platform ALL :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3/4", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"ceph-common-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"ceph-common-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"ceph-debugsource-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libcephfs2-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libcephfs2-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"librados2-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"librados2-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libradosstriper1-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libradosstriper1-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"librbd1-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"librbd1-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"librgw2-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"librgw2-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-cephfs-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-cephfs-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-rados-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-rados-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-rbd-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-rbd-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-rgw-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-rgw-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ceph-common-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ceph-common-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ceph-debugsource-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libcephfs2-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libcephfs2-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librados2-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librados2-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libradosstriper1-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libradosstriper1-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librbd1-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librbd1-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librgw2-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librgw2-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-cephfs-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-cephfs-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rados-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rados-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rbd-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rbd-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rgw-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rgw-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"ceph-common-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"ceph-common-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"ceph-debugsource-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libcephfs2-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libcephfs2-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"librados2-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"librados2-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libradosstriper1-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libradosstriper1-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"librbd1-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"librbd1-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"librgw2-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"librgw2-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-cephfs-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-cephfs-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-rados-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-rados-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-rbd-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-rbd-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-rgw-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-rgw-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ceph-common-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ceph-common-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ceph-debugsource-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libcephfs2-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libcephfs2-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librados2-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librados2-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libradosstriper1-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libradosstriper1-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librbd1-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librbd1-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librgw2-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librgw2-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-cephfs-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-cephfs-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-rados-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-rados-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-rbd-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-rbd-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-rgw-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-rgw-debuginfo-12.2.10+git.1549630712.bb089269ea-2.27.2")) flag++;


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
