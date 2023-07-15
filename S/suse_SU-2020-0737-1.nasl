#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0737-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(134824);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2012-6708",
    "CVE-2015-9251",
    "CVE-2019-15845",
    "CVE-2019-16201",
    "CVE-2019-16254",
    "CVE-2019-16255",
    "CVE-2020-8130"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : Recommended update for ruby2.5 (SUSE-SU-2020:0737-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for ruby2.5 toversion 2.5.7 fixes the following issues :

ruby 2.5 was updated to version 2.5.7

CVE-2020-8130: Fixed a command injection in intree copy of rake
(bsc#1164804).

CVE-2019-16255: Fixed a code injection vulnerability of Shell#[] and
Shell#test (bsc#1152990).

CVE-2019-16254: Fixed am HTTP response splitting in WEBrick
(bsc#1152992).

CVE-2019-15845: Fixed a null injection vulnerability of File.fnmatch
and File.fnmatch? (bsc#1152994).

CVE-2019-16201: Fixed a regular expression denial of service of
WEBrick Digest access authentication (bsc#1152995).

CVE-2012-6708: Fixed an XSS in JQuery

CVE-2015-9251: Fixed an XSS in JQuery

Fixed unit tests (bsc#1140844)

Removed some unneeded test files (bsc#1162396).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1140844");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1152990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1152992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1152994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1152995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1164804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2012-6708/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-9251/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15845/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16201/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16254/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16255/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8130/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200737-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74db8108");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15:zypper in -t patch
SUSE-SLE-Product-SLES_SAP-15-2020-737=1

SUSE Linux Enterprise Server 15-LTSS:zypper in -t patch
SUSE-SLE-Product-SLES-15-2020-737=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-737=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2020-737=1

SUSE Linux Enterprise High Performance Computing 15-LTSS:zypper in -t
patch SUSE-SLE-Product-HPC-15-2020-737=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS:zypper in -t
patch SUSE-SLE-Product-HPC-15-2020-737=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8130");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-16255");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libruby2_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libruby2_5-2_5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.5-devel-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.5-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.5-stdlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"libruby2_5-2_5-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libruby2_5-2_5-debuginfo-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ruby2.5-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ruby2.5-debuginfo-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ruby2.5-debugsource-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ruby2.5-devel-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ruby2.5-devel-extra-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ruby2.5-doc-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ruby2.5-stdlib-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ruby2.5-stdlib-debuginfo-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libruby2_5-2_5-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libruby2_5-2_5-debuginfo-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"ruby2.5-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"ruby2.5-debuginfo-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"ruby2.5-debugsource-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"ruby2.5-devel-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"ruby2.5-devel-extra-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"ruby2.5-stdlib-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"ruby2.5-stdlib-debuginfo-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libruby2_5-2_5-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libruby2_5-2_5-debuginfo-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ruby2.5-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ruby2.5-debuginfo-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ruby2.5-debugsource-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ruby2.5-devel-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ruby2.5-devel-extra-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ruby2.5-doc-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ruby2.5-stdlib-2.5.7-4.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ruby2.5-stdlib-debuginfo-2.5.7-4.8.1")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Recommended update for ruby2.5");
}
