#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1473-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149274);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/07");

  script_cve_id("CVE-2020-25678", "CVE-2020-27839", "CVE-2021-20288");

  script_name(english:"SUSE SLES15 Security Update : ceph (SUSE-SU-2021:1473-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ceph fixes the following issues :

ceph was updated to 14.2.20-402-g6aa76c6815 :

  - CVE-2021-20288: Fixed unauthorized global_id reuse
    (bsc#1183074).

  - CVE-2020-25678: Do not add sensitive information in Ceph
    log files (bsc#1178905).

  - CVE-2020-27839: Use secure cookies to store JWT Token
    (bsc#1179997).

  - mgr/dashboard: prometheus alerting: add some leeway for
    package drops and errors (bsc#1145463)

  - mon: have 'mon stat' output json as well (bsc#1174466)

  - rpm: ceph-mgr-dashboard recommends python3-saml on SUSE
    (bsc#1177200)

  - mgr/dashboard: Display a warning message in Dashboard
    when debug mode is enabled (bsc#1178235)

  - rgw: cls/user: set from_index for reset stats calls
    (bsc#1178837)

  - mgr/dashboard: Disable TLS 1.0 and 1.1 (bsc#1178860)

  - bluestore: provide a different name for fallback
    allocator (bsc#1180118)

  - test/run-cli-tests: use cram from github (bsc#1181378)

  - mgr/dashboard: fix 'Python2 Cookie module import fails
    on Python3' (bsc#1183487)

  - common: make ms_bind_msgr2 default to 'false'
    (bsc#1180594)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1145463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1180118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1180594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1181378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1183074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1183487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25678/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27839/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-20288/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211473-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0c1507d"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Manager Server 4.0 :

zypper in -t patch
SUSE-SLE-Product-SUSE-Manager-Server-4.0-2021-1473=1

SUSE Manager Retail Branch Server 4.0 :

zypper in -t patch
SUSE-SLE-Product-SUSE-Manager-Retail-Branch-Server-4.0-2021-1473=1

SUSE Manager Proxy 4.0 :

zypper in -t patch SUSE-SLE-Product-SUSE-Manager-Proxy-4.0-2021-1473=1

SUSE Linux Enterprise Server for SAP 15-SP1 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-SP1-2021-1473=1

SUSE Linux Enterprise Server 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-LTSS-2021-1473=1

SUSE Linux Enterprise Server 15-SP1-BCL :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-BCL-2021-1473=1

SUSE Linux Enterprise High Performance Computing 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-LTSS-2021-1473=1

SUSE Linux Enterprise High Performance Computing 15-SP1-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-ESPOS-2021-1473=1

SUSE Enterprise Storage 6 :

zypper in -t patch SUSE-Storage-6-2021-1473=1

SUSE CaaS Platform 4.0 :

To install this update, use the SUSE CaaS Platform 'skuba' tool. I
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-cephfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rados-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rados-objclass-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-common-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-common-debuginfo-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-debugsource-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcephfs-devel-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcephfs2-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcephfs2-debuginfo-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librados-devel-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librados-devel-debuginfo-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librados2-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librados2-debuginfo-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libradospp-devel-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librbd-devel-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librbd1-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librbd1-debuginfo-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librgw-devel-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librgw2-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librgw2-debuginfo-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-ceph-argparse-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-cephfs-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-cephfs-debuginfo-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rados-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rados-debuginfo-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rbd-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rbd-debuginfo-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rgw-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rgw-debuginfo-14.2.20.402+g6aa76c6815-3.60.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rados-objclass-devel-14.2.20.402+g6aa76c6815-3.60.1")) flag++;


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
