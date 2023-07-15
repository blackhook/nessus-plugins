#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2003-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(127746);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/24 11:01:33");

  script_cve_id("CVE-2018-16858");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libreoffice (SUSE-SU-2019:2003-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libreoffice fixes the following issues :

LibreOffice was updated to 6.2.5.2 (fate#327121).

Security issue fixed :

CVE-2018-16858: LibreOffice was vulnerable to a directory traversal
attack which could be used to execute arbitrary macros bundled with a
document. An attacker could craft a document, which when opened by
LibreOffice, would execute a Python method from a script in any
arbitrary file system location, specified relative to the LibreOffice
install location. (bsc#1124062)

Other bugfixes: If there is no firebird engine we still need java to
run hsqldb (bsc#1135189)

Require firebird as default driver for base if enabled

PPTX: Rectangle turns from green to blue and loses transparency when
transparency is set (bsc1135228)

Slide deck compression doesn't, hmm, compress too much (bsc#1127760)

Psychedelic graphics in LibreOffice (but not PowerPoint) (bsc#1124869)

Image from PPTX shown in a square, not a circle (bsc#1121874)

Switch to the new web based help system bsc#1116451

Enable new approach for mariadb connector again

PPTX: SmartArt: Basic rendering of the Organizational Chart
(bsc#1112114)

PPTX: SmartArt: Basic rendering of Accent Process and Continuous Block
Process (bsc#1112113)

Saving a new document can silently overwrite an existing document
(bsc#1117300)

Install also C++ libreofficekit headers bsc#1117195

Chart in PPTX lacks color and is too large (bsc#882383)

PPTX: SmartArt: Basic rendering of several list types (bsc#1112112)

PPTX: Charts having weird/darker/ugly background versus Office 365 and
strange artefacts where overlapping (bsc#1110348)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1110348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1116451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1117195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1117300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1124062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1124658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1124869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=882383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16858/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192003-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e41fa24e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15-SP1:zypper in -t patch
SUSE-SLE-Product-WE-15-SP1-2019-2003=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2003=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'LibreOffice Macro Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-gtk2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-sdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreofficekit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-0_4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-0_4-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libreoffice-debuginfo-6.2.5.2-8.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libreoffice-debugsource-6.2.5.2-8.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libreoffice-gtk2-6.2.5.2-8.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libreoffice-gtk2-debuginfo-6.2.5.2-8.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libreoffice-sdk-6.2.5.2-8.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libreoffice-sdk-debuginfo-6.2.5.2-8.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libreoffice-sdk-doc-6.2.5.2-8.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libreofficekit-devel-6.2.5.2-8.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"libwps-0_4-4-0.4.10-7.3.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"libwps-0_4-4-debuginfo-0.4.10-7.3.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"libwps-devel-0.4.10-7.3.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwps-debuginfo-0.4.10-7.3.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwps-debugsource-0.4.10-7.3.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwps-tools-0.4.10-7.3.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwps-tools-debuginfo-0.4.10-7.3.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libreoffice-debuginfo-6.2.5.2-8.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libreoffice-debugsource-6.2.5.2-8.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libreoffice-gtk2-6.2.5.2-8.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libreoffice-gtk2-debuginfo-6.2.5.2-8.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libreoffice-sdk-6.2.5.2-8.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libreoffice-sdk-debuginfo-6.2.5.2-8.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libreoffice-sdk-doc-6.2.5.2-8.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libreofficekit-devel-6.2.5.2-8.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"libwps-0_4-4-0.4.10-7.3.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"libwps-0_4-4-debuginfo-0.4.10-7.3.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"libwps-devel-0.4.10-7.3.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libwps-debuginfo-0.4.10-7.3.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libwps-debugsource-0.4.10-7.3.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libwps-tools-0.4.10-7.3.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libwps-tools-debuginfo-0.4.10-7.3.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreoffice");
}
