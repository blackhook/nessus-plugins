#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2315-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102911);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2015-8947", "CVE-2016-10327", "CVE-2016-2052", "CVE-2017-7870", "CVE-2017-7882", "CVE-2017-8358", "CVE-2017-9433");

  script_name(english:"SUSE SLED12 Security Update : libreoffice (SUSE-SU-2017:2315-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LibreOffice was updated to version 5.3.5.2, bringing new features and
enhancements: Writer :

  - New 'Go to Page' dialog for quickly jumping to another
    page.

  - Support for 'Table Styles'.

  - New drawing tools were added.

  - Improvements in the toolbar.

  - Borderless padding is displayed. Calc :

  - New drawing tools were added.

  - In new installations the default setting for new
    documents is now 'Enable wildcards in formulas' instead
    of regular expressions.

  - Improved compatibility with ODF 1.2 Impress :

  - Images inserted via 'Photo Album' can now be linked
    instead of embedded in the document.

  - When launching Impress, a Template Selector allows you
    to choose a Template to start with.

  - Two new default templates: Vivid and Pencil.

  - All existing templates have been improved. Draw :

  - New arrow endings, including Crow's foot notation's
    ones. Base :

  - Firebird has been upgraded to version 3.0.0. It is
    unable to read back Firebird 2.5 data, so embedded
    Firebird odb files created in LibreOffice version up to
    5.2 cannot be opened with LibreOffice 5.3. Some security
    issues have also been fixed :

  - CVE-2017-7870: An out-of-bounds write caused by a
    heap-based buffer overflow related to the
    tools::Polygon::Insert function.

  - CVE-2017-7882: An out-of-bounds write related to the
    HWPFile::TagsRead function.

  - CVE-2017-8358: an out-of-bounds write caused by a
    heap-based buffer overflow related to the ReadJPEG
    function.

  - CVE-2016-10327: An out-of-bounds write caused by a
    heap-based buffer overflow related to the
    EnhWMFReader::ReadEnhWMF function.

  - CVE-2017-9433: An out-of-bounds write caused by a
    heap-based buffer overflow related to the
    MsWrd1Parser::readFootnoteCorrespondance function in
    libmwaw. A comprehensive list of new features and
    changes in this release is available at:
    https://wiki.documentfoundation.org/ReleaseNotes/5.3

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1015115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1015118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1015360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1017925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1021369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1021373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1021675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1028817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1034192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1034329"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1034568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1035087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1035589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1036975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1042828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=947117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=948058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=954776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=959926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=962777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=963436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=972777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=975283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=976831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=989564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.documentfoundation.org/ReleaseNotes/5.3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8947/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10327/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2052/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7870/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7882/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8358/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9433/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172315-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87a5320b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2017-1427=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2017-1427=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-1427=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-0_12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-0_12-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-0_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-0_3-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-0_12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-0_12-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-drivers-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-drivers-mysql-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreofficekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstaroffice-0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstaroffice-0_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstaroffice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzmf-0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzmf-0_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzmf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-dictionaries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-ru_RU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libixion-0_12-0-0.12.1-13.2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libixion-0_12-0-debuginfo-0.12.1-13.2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libixion-debugsource-0.12.1-13.2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libmwaw-0_3-3-0.3.11-7.5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libmwaw-0_3-3-debuginfo-0.3.11-7.5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libmwaw-debugsource-0.3.11-7.5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"liborcus-0_12-0-0.12.1-10.5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"liborcus-0_12-0-debuginfo-0.12.1-10.5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"liborcus-debugsource-0.12.1-10.5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-base-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-base-debuginfo-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-base-drivers-mysql-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-base-drivers-mysql-debuginfo-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-debuginfo-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-calc-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-calc-debuginfo-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-calc-extensions-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-debuginfo-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-debugsource-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-draw-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-draw-debuginfo-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-filters-optional-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-gnome-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-gnome-debuginfo-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-impress-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-impress-debuginfo-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-mailmerge-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-math-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-math-debuginfo-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-officebean-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-officebean-debuginfo-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-pyuno-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-pyuno-debuginfo-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-writer-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-writer-debuginfo-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-writer-extensions-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreofficekit-5.3.5.2-43.5.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libstaroffice-0_0-0-0.0.3-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libstaroffice-0_0-0-debuginfo-0.0.3-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libstaroffice-debugsource-0.0.3-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libzmf-0_0-0-0.0.1-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libzmf-0_0-0-debuginfo-0.0.1-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libzmf-debugsource-0.0.1-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"myspell-dictionaries-20170511-16.2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"myspell-lightproof-en-20170511-16.2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"myspell-lightproof-hu_HU-20170511-16.2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"myspell-lightproof-pt_BR-20170511-16.2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"myspell-lightproof-ru_RU-20170511-16.2.1")) flag++;


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
