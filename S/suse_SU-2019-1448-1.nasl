#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1448-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(125798);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/10 13:51:51");

  script_cve_id("CVE-2018-16858");

  script_name(english:"SUSE SLED12 Security Update : LibreOffice (SUSE-SU-2019:1448-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libreoffice and libraries fixes the following issues :

LibreOffice was updated to 6.2.3.2 (fate#327121 bsc#1128845
bsc#1123455), bringing lots of bug and stability fixes.

Additional bugfixes :

If there is no firebird engine we still need java to run hsqldb
(bsc#1135189)

PPTX: Rectangle turns from green to blue and loses transparency when
transparency is set (bsc#1135228)

Slide deck compression doesn't, hmm, compress too much (bsc#1127760)

Psychedelic graphics in LibreOffice (but not PowerPoint) (bsc#1124869)

Image from PPTX shown in a square, not a circle (bsc#1121874)

libixion was updated to 0.14.1: Updated for new orcus

liborcus was updated to 0.14.1: Boost 1.67 support

Various cell handling issues fixed

libwps was updated to 0.4.10: QuattroPro: add parser of .qwp files

all: support complex encoding

mdds was updated to 1.4.3: Api change to 1.4

More multivector opreations and tweaks

Various multi vector fixes

flat_segment_tree: add segment iterator and functions

fix to handle out-of-range insertions on flat_segment_tree

Another api version -> rename to mdds-1_2

myspell-dictionaries was updated to 20190423: Serbian dictionary
updated

Update af_ZA hunspell

Update Spanish dictionary

Update Slovenian dictionary

Update Breton dictionary

Update Galician dictionary

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1089811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1116451"
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
    value:"https://www.suse.com/security/cve/CVE-2018-16858/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191448-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8bbeb6ff"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP4:zypper in -t patch
SUSE-SLE-WE-12-SP4-2019-1448=1

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2019-1448=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-1448=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2019-1448=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-1448=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2019-1448=1"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-0_14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-0_14-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-0_14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-0_14-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-drivers-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-calc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-draw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-gtk2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-impress-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-math-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-officebean-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-pyuno-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-writer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-0_4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-0_4-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-dictionaries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-ru_RU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/10");
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
if (! preg(pattern:"^(SLED12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libixion-0_14-0-0.14.1-13.9.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libixion-0_14-0-debuginfo-0.14.1-13.9.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libixion-debugsource-0.14.1-13.9.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"liborcus-0_14-0-0.14.1-10.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"liborcus-0_14-0-debuginfo-0.14.1-10.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"liborcus-debugsource-0.14.1-10.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-base-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-base-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-calc-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-calc-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-calc-extensions-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-debugsource-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-draw-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-draw-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-filters-optional-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-gnome-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-gnome-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-gtk2-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-gtk2-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-impress-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-impress-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-mailmerge-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-math-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-math-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-officebean-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-officebean-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-pyuno-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-pyuno-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-writer-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-writer-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-writer-extensions-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libwps-0_4-4-0.4.10-10.13.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libwps-0_4-4-debuginfo-0.4.10-10.13.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libwps-debugsource-0.4.10-10.13.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"myspell-dictionaries-20190423-16.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"myspell-lightproof-en-20190423-16.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"myspell-lightproof-hu_HU-20190423-16.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"myspell-lightproof-pt_BR-20190423-16.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"myspell-lightproof-ru_RU-20190423-16.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libixion-0_14-0-0.14.1-13.9.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libixion-0_14-0-debuginfo-0.14.1-13.9.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libixion-debugsource-0.14.1-13.9.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"liborcus-0_14-0-0.14.1-10.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"liborcus-0_14-0-debuginfo-0.14.1-10.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"liborcus-debugsource-0.14.1-10.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-base-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-base-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-calc-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-calc-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-calc-extensions-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-debugsource-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-draw-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-draw-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-filters-optional-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-gnome-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-gnome-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-gtk2-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-gtk2-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-impress-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-impress-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-mailmerge-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-math-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-math-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-officebean-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-officebean-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-pyuno-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-pyuno-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-writer-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-writer-debuginfo-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-writer-extensions-6.2.3.2-43.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwps-0_4-4-0.4.10-10.13.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwps-0_4-4-debuginfo-0.4.10-10.13.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwps-debugsource-0.4.10-10.13.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"myspell-dictionaries-20190423-16.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"myspell-lightproof-en-20190423-16.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"myspell-lightproof-hu_HU-20190423-16.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"myspell-lightproof-pt_BR-20190423-16.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"myspell-lightproof-ru_RU-20190423-16.18.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LibreOffice");
}
