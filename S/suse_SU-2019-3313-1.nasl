#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:3313-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(132094);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-9853");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : LibreOffice (SUSE-SU-2019:3313-1)");
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

Other issues addressed: Dropped disable-kde4 switch, since it is no
longer known by configure

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
  # https://www.suse.com/support/update/announcement/2019/suse-su-20193313-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50780237"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15-SP1:zypper in -t patch
SUSE-SLE-Product-WE-15-SP1-2019-3313=1

SUSE Linux Enterprise Workstation Extension 15:zypper in -t patch
SUSE-SLE-Product-WE-15-2019-3313=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-3313=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-3313=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-3313=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-3313=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cmis-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cmis-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cmis-client-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcmis-c-0_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcmis-c-0_5-5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcmis-c-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-0_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-0_3-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-dictionaries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-ru_RU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-libixion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-libixion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-liborcus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-liborcus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"libmwaw-0_3-3-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"libmwaw-0_3-3-debuginfo-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cmis-client-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cmis-client-debuginfo-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cmis-client-debugsource-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcmis-c-0_5-5-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcmis-c-0_5-5-debuginfo-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcmis-c-devel-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libixion-debuginfo-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libixion-debugsource-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libixion-devel-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libixion-tools-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libixion-tools-debuginfo-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmwaw-debuginfo-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmwaw-debugsource-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmwaw-devel-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmwaw-tools-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmwaw-tools-debuginfo-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"liborcus-debuginfo-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"liborcus-debugsource-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"liborcus-tools-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"liborcus-tools-debuginfo-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"myspell-dictionaries-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"myspell-lightproof-en-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"myspell-lightproof-hu_HU-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"myspell-lightproof-pt_BR-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"myspell-lightproof-ru_RU-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-libixion-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-libixion-debuginfo-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-liborcus-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-liborcus-debuginfo-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cmis-client-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cmis-client-debuginfo-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cmis-client-debugsource-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcmis-c-0_5-5-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcmis-c-0_5-5-debuginfo-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcmis-c-devel-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libixion-debuginfo-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libixion-debugsource-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libixion-devel-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libixion-tools-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libixion-tools-debuginfo-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmwaw-debuginfo-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmwaw-debugsource-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmwaw-devel-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmwaw-tools-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmwaw-tools-debuginfo-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"liborcus-debuginfo-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"liborcus-debugsource-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"liborcus-tools-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"liborcus-tools-debuginfo-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"myspell-dictionaries-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"myspell-lightproof-en-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"myspell-lightproof-hu_HU-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"myspell-lightproof-pt_BR-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"myspell-lightproof-ru_RU-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-libixion-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-libixion-debuginfo-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-liborcus-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-liborcus-debuginfo-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"libmwaw-0_3-3-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"libmwaw-0_3-3-debuginfo-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cmis-client-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cmis-client-debuginfo-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cmis-client-debugsource-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcmis-c-0_5-5-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcmis-c-0_5-5-debuginfo-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcmis-c-devel-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libixion-debuginfo-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libixion-debugsource-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libixion-devel-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libixion-tools-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libixion-tools-debuginfo-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libmwaw-debuginfo-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libmwaw-debugsource-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libmwaw-devel-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libmwaw-tools-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libmwaw-tools-debuginfo-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"liborcus-debuginfo-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"liborcus-debugsource-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"liborcus-tools-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"liborcus-tools-debuginfo-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"myspell-dictionaries-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"myspell-lightproof-en-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"myspell-lightproof-hu_HU-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"myspell-lightproof-pt_BR-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"myspell-lightproof-ru_RU-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-libixion-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-libixion-debuginfo-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-liborcus-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-liborcus-debuginfo-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cmis-client-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cmis-client-debuginfo-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cmis-client-debugsource-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcmis-c-0_5-5-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcmis-c-0_5-5-debuginfo-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcmis-c-devel-0.5.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libixion-debuginfo-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libixion-debugsource-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libixion-devel-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libixion-tools-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libixion-tools-debuginfo-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmwaw-debuginfo-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmwaw-debugsource-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmwaw-devel-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmwaw-tools-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmwaw-tools-debuginfo-0.3.15-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"liborcus-debuginfo-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"liborcus-debugsource-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"liborcus-tools-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"liborcus-tools-debuginfo-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"myspell-dictionaries-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"myspell-lightproof-en-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"myspell-lightproof-hu_HU-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"myspell-lightproof-pt_BR-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"myspell-lightproof-ru_RU-20191016-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-libixion-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-libixion-debuginfo-0.15.0-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-liborcus-0.15.3-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-liborcus-debuginfo-0.15.3-3.6.1")) flag++;


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
