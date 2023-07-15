#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0372-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(133601);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/30");

  script_cve_id("CVE-2019-9853");

  script_name(english:"SUSE SLES12 Security Update : LibreOffice (SUSE-SU-2020:0372-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update libreoffice and libraries fixes the following issues :

LibreOffice was updated to 6.3.3 (jsc#SLE-8705), bringing many bug and
stability fixes.

More information for the 6.3 release at:
https://wiki.documentfoundation.org/ReleaseNotes/6.3

Security issue fixed :

CVE-2019-9853: Fixed an issue where by executing macros, the security
settings could have been bypassed (bsc#1152684).

Other issues addressed :

Dropped disable-kde4 switch, since it is no longer known by configure

Disabled gtk2 because it will be removed in future releases

librelogo is now a standalone sub-package (bsc#1144522).

Partial fixes for an issue where Table(s) from DOCX showed wrong
position or color (bsc#1061210).

cmis-client was updated to 0.5.2 :

  - Removed header for Uuid's sha1 header(bsc#1105173).

  - Fixed Google Drive login

  - Added support for Google Drive two-factor authentication

  - Fixed access to SharePoint root folder

  - Limited the maximal number of redirections to 20

  - Switched library implementation to C++11 (the API
    remains C++98-compatible)

  - Fixed encoding of OAuth2 credentials

  - Dropped cppcheck run from 'make check'. A new 'make
    cppcheck' target was created for it

  - Added proper API symbol exporting

  - Speeded up building of tests a bit

  - Fixed a few issues found by coverity and cppcheck

libixion was updated to 0.15.0 :

  - Updated for new liborcus

  - Switched to spdlog for compile-time debug log outputs

  - Fixed various issues

libmwaw was updated 0.3.15 :

  - Fixed fuzzing issues

liborcus was updated to 0.15.3 :

  - Fixed various xml related bugs

  - Improved performance

  - Fixed multiple parser issues

  - Added map and structure mode to orcus-json

  - Other improvements and fixes

mdds was updated to 1.5.0 :

  - API changed to 1.5

  - Moved the API incompatibility notes from README to the
    rst doc.

  - Added the overview section for flat_segment_tree.

myspell-dictionaries was updated to 20191016 :

  - Updated Slovenian thesaurus

  - Updated the da_DK dictionary

  - Removed the abbreviations from Thai hunspell dictionary

  - Updated the English dictionaries

  - Fixed the logo management for 'ca'

spdlog was updated to 0.16.3 :

  - Fixed sleep issue under MSVC that happens when changing
    the clock backwards

  - Ensured that macros always expand to expressions

  - Added global flush_on function

bluez changes :

  - lib: Changed bluetooth.h to compile in strict C

gperf was updated to 3.1 :

  - The generated C code is now in ANSI-C by default.

  - Added option --constants-prefix.

  - Added declaration %define constants-prefix.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1144522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1152684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.documentfoundation.org/ReleaseNotes/6.3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9853/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200372-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e97979cd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP5 :

zypper in -t patch SUSE-SLE-WE-12-SP5-2020-372=1

SUSE Linux Enterprise Workstation Extension 12-SP4 :

zypper in -t patch SUSE-SLE-WE-12-SP4-2020-372=1

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2020-372=1

SUSE Linux Enterprise Software Development Kit 12-SP4 :

zypper in -t patch SUSE-SLE-SDK-12-SP4-2020-372=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2020-372=1

SUSE Linux Enterprise Server 12-SP4 :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-2020-372=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bluez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bluez-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bluez-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libbluetooth3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libbluetooth3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"bluez-5.13-5.20.6")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"bluez-debuginfo-5.13-5.20.6")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"bluez-debugsource-5.13-5.20.6")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libbluetooth3-5.13-5.20.6")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libbluetooth3-debuginfo-5.13-5.20.6")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"bluez-5.13-5.20.6")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"bluez-debuginfo-5.13-5.20.6")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"bluez-debugsource-5.13-5.20.6")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libbluetooth3-5.13-5.20.6")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libbluetooth3-debuginfo-5.13-5.20.6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LibreOffice");
}
