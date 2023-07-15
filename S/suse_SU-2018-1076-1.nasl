#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1076-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(109357);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2017-9432", "CVE-2017-9433", "CVE-2018-1055", "CVE-2018-6871");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : Recommended update for LibreOffice (SUSE-SU-2018:1076-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"LibreOffice was updated to version 6.0.3. Following new features were
added :

  - The Notebookbar, although still an experimental feature,
    has been enriched with two new variants: Grouped Bar
    Full for Writer, Calc and Impress, and Tabbed Compact
    for Writer. The Special Characters dialog has been
    reworked, with the addition of lists for Recent and
    Favorite characters, along with a Search field. The
    Customize dialog has also been redesigned, and is now
    more modern and intuitive.

  - In Writer, a Form menu has been added, making it easier
    to access one of the most powerful
    &Atilde;&cent;&Acirc;&#128;&Acirc;&#147; and often
    unknown &Atilde;&cent;&Acirc;&#128;&Acirc;&#147;
    LibreOffice features: the ability to design forms, and
    create standards-compliant PDF forms. The Find toolbar
    has been enhanced with a drop-down list of search types,
    to speed up navigation. A new default table style has
    been added, together with a new collection of table
    styles to reflect evolving visual trends.

  - The Mail Merge function has been improved, and it is now
    possible to use either a Writer document or an XLSX file
    as data source.

  - In Calc, ODF 1.2-compliant functions SEARCHB, FINDB and
    REPLACEB have been added, to improve support for the ISO
    standard format. Also, a cell range selection or a
    selected group of shapes (images) can be now exported in
    PNG or JPG format.

  - In Impress, the default slide size has been switched to
    16:9, to support the most recent form factors of screens
    and projectors. As a consequence, 10 new Impress
    templates have been added, and a couple of old templates
    have been updated. Changes in components :

  - The old WikiHelp has been replaced by the new Help
    Online system, with attractive web pages that can also
    be displayed on mobile devices. In general, LibreOffice
    Help has been updated both in terms of contents and
    code, with other improvements due all along the life of
    the LibreOffice 6 family.

  - User dictionaries now allow automatic affixation or
    compounding. This is a general spell checking
    improvement in LibreOffice which can speed up work for
    Writer users. Instead of manually handling several forms
    of a new word in a language with rich morphology or
    compounding, the Hunspell spell checker can
    automatically recognize a new word with affixes or
    compounds, based on a
    &Atilde;&cent;&Acirc;&#128;&Acirc;&#156;Grammar
    By&Atilde;&cent;&Acirc;&#128;&Acirc;&#157; model.
    Security features and changes :

  - OpenPGP keys can be used to sign ODF documents on all
    desktop operating systems, with experimental support for
    OpenPGP-based encryption. To enable this feature, users
    will have to install the specific GPG software for their
    operating systems.

  - Document classification has also been improved, and
    allows multiple policies (which are now exported to
    OOXML files). In Writer, marking and signing are now
    supported at paragraph level. Interoperability changes :

  - OOXML interoperability has been improved in several
    areas: import of SmartArt and import/export of ActiveX
    controls, support of embedded text documents and
    spreadsheets, export of embedded videos to PPTX, export
    of cross-references to DOCX, export of MailMerge fields
    to DOCX, and improvements to the PPTX filter to prevent
    the creation of broken files.

  - New filters for exporting Writer documents to ePub and
    importing QuarkXPress files have also been added,
    together with an improved filter for importing EMF+
    (Enhanced Metafile Format Plus) files as used by
    Microsoft Office documents. Some improvements have also
    been added to the ODF export filter, making it easier
    for other ODF readers to display visuals. The full blog
    entry for the 6.0 release can be found here:
    &#9;https://blog.documentfoundation.org/blog/2018/01/31/
    libreoffice-6/ The full release notes can be found here:
    &#9;https://wiki.documentfoundation.org/ReleaseNotes/6.0
    The libraries that LibreOffice depends on also have been
    udpated to their current versions.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blog.documentfoundation.org/blog/2018/01/31/libreoffice-6/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1042829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1077375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1080249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1088662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1089124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.documentfoundation.org/ReleaseNotes/6.0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9432/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9433/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1055/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6871/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181076-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?94e071c5"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2018-735=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-735=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-735=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-735=1

SUSE CaaS Platform ALL :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnome-documents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnome-documents-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnome-documents_books-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnome-documents_books-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnome-shell-search-provider-documents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_atomic1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_atomic1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_date_time1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_date_time1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_filesystem1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_filesystem1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_iostreams1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_iostreams1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_locale1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_locale1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_program_options1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_program_options1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_random1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_random1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_regex1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_regex1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_signals1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_signals1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_system1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_system1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_thread1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_thread1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libepubgen-0_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libepubgen-0_1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libepubgen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-0_13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-0_13-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-0_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-0_3-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-0_13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-0_13-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqxp-0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqxp-0_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqxp-debugsource");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstaroffice-0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstaroffice-0_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstaroffice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-0_4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-0_4-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-dictionaries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-ru_RU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_atomic1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_atomic1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_date_time1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_date_time1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_iostreams1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_iostreams1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_program_options1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_program_options1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_random1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_random1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_regex1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_regex1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_signals1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_signals1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_system1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_system1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_thread1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libboost_thread1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gnome-documents-3.20.1-10.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gnome-documents-debugsource-3.20.1-10.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gnome-documents_books-common-3.20.1-10.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gnome-documents_books-common-debuginfo-3.20.1-10.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gnome-shell-search-provider-documents-3.20.1-10.6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_atomic1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_atomic1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_date_time1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_date_time1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_filesystem1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_filesystem1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_iostreams1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_iostreams1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_locale1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_locale1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_program_options1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_program_options1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_random1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_random1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_regex1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_regex1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_signals1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_signals1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_system1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_system1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_thread1_54_0-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libboost_thread1_54_0-debuginfo-1.54.0-26.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libepubgen-0_1-1-0.1.0-6.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libepubgen-0_1-1-debuginfo-0.1.0-6.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libepubgen-debugsource-0.1.0-6.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libixion-0_13-0-0.13.0-13.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libixion-0_13-0-debuginfo-0.13.0-13.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libixion-debugsource-0.13.0-13.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libmwaw-0_3-3-0.3.13-7.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libmwaw-0_3-3-debuginfo-0.3.13-7.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libmwaw-debugsource-0.3.13-7.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"liborcus-0_13-0-0.13.4-10.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"liborcus-0_13-0-debuginfo-0.13.4-10.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"liborcus-debugsource-0.13.4-10.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqxp-0_0-0-0.0.1-1.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqxp-0_0-0-debuginfo-0.0.1-1.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqxp-debugsource-0.0.1-1.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-base-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-base-debuginfo-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-base-drivers-mysql-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-base-drivers-mysql-debuginfo-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-debuginfo-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-calc-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-calc-debuginfo-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-calc-extensions-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-debuginfo-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-debugsource-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-draw-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-draw-debuginfo-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-filters-optional-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-gnome-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-gnome-debuginfo-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-gtk2-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-gtk2-debuginfo-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-impress-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-impress-debuginfo-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-mailmerge-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-math-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-math-debuginfo-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-officebean-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-officebean-debuginfo-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-pyuno-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-pyuno-debuginfo-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-writer-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-writer-debuginfo-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libreoffice-writer-extensions-6.0.3.2-43.30.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libstaroffice-0_0-0-0.0.5-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libstaroffice-0_0-0-debuginfo-0.0.5-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libstaroffice-debugsource-0.0.5-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwps-0_4-4-0.4.7-10.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwps-0_4-4-debuginfo-0.4.7-10.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwps-debugsource-0.4.7-10.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"myspell-dictionaries-20180403-16.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"myspell-lightproof-en-20180403-16.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"myspell-lightproof-hu_HU-20180403-16.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"myspell-lightproof-pt_BR-20180403-16.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"myspell-lightproof-ru_RU-20180403-16.9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Recommended update for LibreOffice");
}
