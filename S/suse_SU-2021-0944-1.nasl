#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0944-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(148175);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-27840", "CVE-2021-20277");
  script_xref(name:"IAVA", value:"2021-A-0140-S");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ldb (SUSE-SU-2021:0944-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ldb fixes the following issues :

CVE-2020-27840: Fixed an unauthenticated remote heap corruption via
bad DNs (bsc#1183572).

CVE-2021-20277: Fixed an out of bounds read in ldb_handler_fold
(bsc#1183574).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1183572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1183574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27840/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-20277/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210944-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?481ed88d"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Manager Server 4.0 :

zypper in -t patch SUSE-SLE-Product-SUSE-Manager-Server-4.0-2021-944=1

SUSE Manager Retail Branch Server 4.0 :

zypper in -t patch
SUSE-SLE-Product-SUSE-Manager-Retail-Branch-Server-4.0-2021-944=1

SUSE Manager Proxy 4.0 :

zypper in -t patch SUSE-SLE-Product-SUSE-Manager-Proxy-4.0-2021-944=1

SUSE Linux Enterprise Server for SAP 15-SP1 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-SP1-2021-944=1

SUSE Linux Enterprise Server 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-LTSS-2021-944=1

SUSE Linux Enterprise Server 15-SP1-BCL :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-BCL-2021-944=1

SUSE Linux Enterprise Module for Python2 15-SP3 :

zypper in -t patch SUSE-SLE-Module-Python2-15-SP3-2021-944=1

SUSE Linux Enterprise Module for Python2 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Python2-15-SP2-2021-944=1

SUSE Linux Enterprise High Performance Computing 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-LTSS-2021-944=1

SUSE Linux Enterprise High Performance Computing 15-SP1-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-ESPOS-2021-944=1

SUSE Enterprise Storage 6 :

zypper in -t patch SUSE-Storage-6-2021-944=1

SUSE CaaS Platform 4.0 :

To install this update, use the SUSE CaaS Platform 'skuba' tool. I
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20277");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ldb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ldb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ldb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldb1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-ldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-ldb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-ldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ldb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ldb-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/26");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1/2/3", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libldb1-32bit-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libldb1-32bit-debuginfo-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ldb-debugsource-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ldb-tools-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ldb-tools-debuginfo-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libldb-devel-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libldb1-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libldb1-debuginfo-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-ldb-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-ldb-debuginfo-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-ldb-devel-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-ldb-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-ldb-debuginfo-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-ldb-devel-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"ldb-debugsource-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libldb1-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libldb1-debuginfo-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python-ldb-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python-ldb-debuginfo-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"ldb-debugsource-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libldb1-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libldb1-debuginfo-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"ldb-debugsource-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libldb1-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libldb1-debuginfo-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python-ldb-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python-ldb-debuginfo-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"ldb-debugsource-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libldb1-1.4.6-3.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libldb1-debuginfo-1.4.6-3.8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldb");
}
