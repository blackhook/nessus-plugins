#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1748-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(138295);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-10753");

  script_name(english:"SUSE SLES12 Security Update : ceph (SUSE-SU-2020:1748-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This is a version update for ceph to version 12.2.13 :

Security issue fixed :

CVE-2020-10753: Fixed an HTTP header injection via CORS ExposeHeader
tag (bsc#1171921).

Notable changes in this update for ceph :

  - mgr: telemetry: backported and now available on SES5.5.
    Please consider enabling via 'ceph telemetry on'
    (bsc#1171670)

  - OSD heartbeat ping time: new health warning, options and
    admin commands (bsc#1171960)

  - 'osd_calc_pg_upmaps_max_stddev' ceph.conf parameter has
    been removed; use 'upmap_max_deviation' instead
    (bsc#1171961)

  - Default maximum concurrent bluestore rocksdb compaction
    threads raised from 1 to 2 for improved ability to keep
    up with rgw bucket index workloads (bsc#1171963)

Bug fixes in this ceph update :

  - mon: Error message displayed when
    mon_osd_max_split_count would be exceeded is not as
    user-friendly as it could be (bsc#1126230)

  - ceph_volume_client: remove ceph mds calls in favor of
    ceph fs calls (bsc#1136082)

  - rgw: crypt: permit RGW-AUTO/default with SSE-S3 headers
    (bsc#1157607)

  - mon/AuthMonitor: don't validate fs caps on authorize
    (bsc#1161096)

Additional bug fixes :

  - ceph-volume: strip _dmcrypt suffix in simple scan json
    output (bsc#1162553)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1136082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1161096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1162553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-10753/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201748-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b6626c3"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-8-2020-1748=1

SUSE OpenStack Cloud 8 :

zypper in -t patch SUSE-OpenStack-Cloud-8-2020-1748=1

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2020-1748=1

SUSE Linux Enterprise Software Development Kit 12-SP4 :

zypper in -t patch SUSE-SLE-SDK-12-SP4-2020-1748=1

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2020-1748=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2020-1748=1

SUSE Linux Enterprise Server 12-SP4 :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-2020-1748=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2020-1748=1

SUSE Linux Enterprise Server 12-SP3-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-BCL-2020-1748=1

SUSE Enterprise Storage 5 :

zypper in -t patch SUSE-Storage-5-2020-1748=1

HPE Helion Openstack 8 :

zypper in -t patch HPE-Helion-OpenStack-8-2020-1748=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10753");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3/4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"ceph-common-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"ceph-common-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"ceph-debugsource-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libcephfs2-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libcephfs2-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"librados2-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"librados2-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libradosstriper1-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libradosstriper1-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"librbd1-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"librbd1-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"librgw2-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"librgw2-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-cephfs-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-cephfs-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-rados-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-rados-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-rbd-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-rbd-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-rgw-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-rgw-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ceph-common-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ceph-common-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ceph-debugsource-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libcephfs2-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libcephfs2-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librados2-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librados2-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libradosstriper1-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libradosstriper1-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librbd1-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librbd1-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librgw2-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librgw2-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-cephfs-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-cephfs-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rados-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rados-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rbd-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rbd-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rgw-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-rgw-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"ceph-common-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"ceph-common-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"ceph-debugsource-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libcephfs2-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libcephfs2-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"librados2-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"librados2-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libradosstriper1-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libradosstriper1-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"librbd1-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"librbd1-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"librgw2-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"librgw2-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-cephfs-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-cephfs-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-rados-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-rados-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-rbd-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-rbd-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-rgw-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-rgw-debuginfo-12.2.13+git.1592168685.85110a3e9d-2.50.1")) flag++;


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