#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1568-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(137597);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-7598",
    "CVE-2020-8174",
    "CVE-2020-10531",
    "CVE-2020-11080"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"SUSE SLES15 Security Update : nodejs10 (SUSE-SU-2020:1568-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for nodejs10 fixes the following issues :

nodejs10 was updated to version 10.21.0

CVE-2020-8174: Fixed multiple memory corruption in
napi_get_value_string_*() (bsc#1172443).

CVE-2020-11080: Fixed a potential denial of service when receiving
unreasonably large HTTP/2 SETTINGS frames (bsc#1172442).

CVE-2020-10531: Fixed an integer overflow in UnicodeString:doAppend()
(bsc#1166844).

Fixed an issue with openssl by adding getrandom syscall definition for
all Linux platforms (bsc#1162117).

npm was updated to 6.14.3

CVE-2020-7598: Fixed an issue which could have tricked minimist into
adding or modifying properties of Object.prototype (bsc#1166916).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1166844");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1166916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172443");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10531/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11080/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-7598/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8174/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201568-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b56bd207");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-1568=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-1568=1

SUSE Linux Enterprise Module for Web Scripting 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Web-Scripting-15-SP2-2020-1568=1

SUSE Linux Enterprise Module for Web Scripting 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Web-Scripting-15-SP1-2020-1568=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-1568=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-1568=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8174");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10531");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs10-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:npm10");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"nodejs10-10.21.0-1.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nodejs10-debuginfo-10.21.0-1.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nodejs10-debugsource-10.21.0-1.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nodejs10-devel-10.21.0-1.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"npm10-10.21.0-1.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"nodejs10-10.21.0-1.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"nodejs10-debuginfo-10.21.0-1.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"nodejs10-debugsource-10.21.0-1.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"nodejs10-devel-10.21.0-1.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"npm10-10.21.0-1.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"nodejs10-10.21.0-1.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"nodejs10-debuginfo-10.21.0-1.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"nodejs10-debugsource-10.21.0-1.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"nodejs10-devel-10.21.0-1.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"npm10-10.21.0-1.21.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs10");
}
