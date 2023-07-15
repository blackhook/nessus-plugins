#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0186-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(145253);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/27");

  script_cve_id("CVE-2018-10536", "CVE-2018-10537", "CVE-2018-10538", "CVE-2018-10539", "CVE-2018-10540", "CVE-2018-19840", "CVE-2018-19841", "CVE-2018-6767", "CVE-2018-7253", "CVE-2018-7254", "CVE-2019-1010319", "CVE-2019-11498", "CVE-2020-35738");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : wavpack (SUSE-SU-2021:0186-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for wavpack fixes the following issues :

Update to version 5.4.0

  - CVE-2020-35738: Fixed an out-of-bounds write in
    WavpackPackSamples (bsc#1180414)

  - fixed: disable A32 asm code when building for Apple
    silicon

  - fixed: issues with Adobe-style floating-point WAV files

  - added: --normalize-floats option to wvunpack for
    correctly exporting un-normalized floating-point files

Update to version 5.3.0

  - fixed: OSS-Fuzz issues 19925, 19928, 20060, 20448

  - fixed: trailing garbage characters on imported ID3v2
    TXXX tags

  - fixed: various minor undefined behavior and memory
    access issues

  - fixed: sanitize tag extraction names for length and path
    inclusion

  - improved: reformat wvunpack 'help' and split into long +
    short versions

  - added: regression testing to Travis CI for OSS-Fuzz
    crashers

Updated to version 5.2.0

*fixed: potential security issues including the following CVEs:
CVE-2018-19840, CVE-2018-19841, CVE-2018-10536 (bsc#1091344),
CVE-2018-10537 (bsc#1091343) CVE-2018-10538 (bsc#1091342),
CVE-2018-10539 (bsc#1091341), CVE-2018-10540 (bsc#1091340),
CVE-2018-7254, CVE-2018-7253, CVE-2018-6767, CVE-2019-11498 and
CVE-2019-1010319

  - added: support for CMake, Travis CI, and Google's
    OSS-fuzz

  - fixed: use correction file for encode verify (pipe
    input, Windows)

  - fixed: correct WAV header with actual length (pipe
    input, -i option)

  - fixed: thumb interworking and not needing v6
    architecture (ARM asm)

  - added: handle more ID3v2.3 tag items and from all file
    types

  - fixed: coredump on Sparc64 (changed MD5 implementation)

  - fixed: handle invalid ID3v2.3 tags from sacd-ripper

  - fixed: several corner-case memory leaks

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1180414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10536/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10537/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10538/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10539/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10540/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19840/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19841/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6767/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7253/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7254/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-1010319/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11498/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-35738/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210186-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67b78d20"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Manager Server 4.0 :

zypper in -t patch SUSE-SLE-Product-SUSE-Manager-Server-4.0-2021-186=1

SUSE Manager Retail Branch Server 4.0 :

zypper in -t patch
SUSE-SLE-Product-SUSE-Manager-Retail-Branch-Server-4.0-2021-186=1

SUSE Manager Proxy 4.0 :

zypper in -t patch SUSE-SLE-Product-SUSE-Manager-Proxy-4.0-2021-186=1

SUSE Linux Enterprise Server for SAP 15-SP1 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-SP1-2021-186=1

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2021-186=1

SUSE Linux Enterprise Server 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-LTSS-2021-186=1

SUSE Linux Enterprise Server 15-SP1-BCL :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-BCL-2021-186=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2021-186=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP3 :

zypper in -t patch
SUSE-SLE-Module-Desktop-Applications-15-SP3-2021-186=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Desktop-Applications-15-SP2-2021-186=1

SUSE Linux Enterprise Module for Basesystem 15-SP3 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP3-2021-186=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-186=1

SUSE Linux Enterprise High Performance Computing 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-LTSS-2021-186=1

SUSE Linux Enterprise High Performance Computing 15-SP1-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-ESPOS-2021-186=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-186=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-186=1

SUSE Enterprise Storage 6 :

zypper in -t patch SUSE-Storage-6-2021-186=1

SUSE CaaS Platform 4.0 :

To install this update, use the SUSE CaaS Platform 'skuba' tool. I
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwavpack1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwavpack1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wavpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wavpack-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wavpack-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wavpack-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/22");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2/3", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwavpack1-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwavpack1-debuginfo-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"wavpack-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"wavpack-debuginfo-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"wavpack-debugsource-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"wavpack-devel-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libwavpack1-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libwavpack1-debuginfo-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"wavpack-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"wavpack-debuginfo-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"wavpack-debugsource-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"wavpack-devel-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libwavpack1-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libwavpack1-debuginfo-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"wavpack-debuginfo-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"wavpack-debugsource-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libwavpack1-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libwavpack1-debuginfo-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"wavpack-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"wavpack-debuginfo-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"wavpack-debugsource-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"wavpack-devel-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libwavpack1-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libwavpack1-debuginfo-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"wavpack-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"wavpack-debuginfo-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"wavpack-debugsource-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"wavpack-devel-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libwavpack1-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libwavpack1-debuginfo-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"wavpack-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"wavpack-debuginfo-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"wavpack-debugsource-5.4.0-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"wavpack-devel-5.4.0-4.9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wavpack");
}
