#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-807.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101517);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-10327", "CVE-2017-7870", "CVE-2017-7882", "CVE-2017-8358", "CVE-2017-9433");

  script_name(english:"openSUSE Security Update : libreoffice (openSUSE-2017-807)");
  script_summary(english:"Check for the openSUSE-2017-807 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LibreOffice was updated to version 5.3.3.2, bringing new features and
enhancements :

Writer :

  - New 'Go to Page' dialog for quickly jumping to another
    page.

  - Support for 'Table Styles'.

  - New drawing tools were added.

  - Improvements in the toolbar.

  - Borderless padding is displayed.

Calc :

  - New drawing tools were added.

  - In new installations the default setting for new
    documents is now 'Enable wildcards in formulas' instead
    of regular expressions.

  - Improved compatibility with ODF 1.2

Impress :

  - Images inserted via 'Photo Album' can now be linked
    instead of embedded in the document.

  - When launching Impress, a Template Selector allows you
    to choose a Template to start with.

  - Two new default templates: Vivid and Pencil.

  - All existing templates have been improved.

Draw :

  - New arrow endings, including Crow's foot notation's
    ones.

Base :

  - Firebird has been upgraded to version 3.0.0. It is
    unable to read back Firebird 2.5 data, so embedded
    Firebird odb files created in LibreOffice version up to
    5.2 cannot be opened with LibreOffice 5.3.

Some security issues have also been fixed :

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
    libmwaw.

A comprehensive list of new features and changes in this release is
available at: https://wiki.documentfoundation.org/ReleaseNotes/5.3

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034329"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=948058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976831"
  );
  # https://features.opensuse.org/318572
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/"
  );
  # https://features.opensuse.org/322101
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/"
  );
  # https://features.opensuse.org/323270
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.documentfoundation.org/ReleaseNotes/5.3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreoffice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-0_12-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-0_12-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmwaw-0_3-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmwaw-0_3-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmwaw-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmwaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmwaw-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmwaw-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-0_12-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-0_12-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gdb-pretty-printers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-glade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-breeze");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-galaxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-hicontrast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-sifr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-tango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-kde4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-math-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-officebean-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-pyuno-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-sdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreofficekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreofficekit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstaroffice-0_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstaroffice-0_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstaroffice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstaroffice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstaroffice-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstaroffice-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzmf-0_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzmf-0_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzmf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzmf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzmf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzmf-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-af_NA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-af_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-an_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_AE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_BH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_DZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_EG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_IQ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_JO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_KW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_LB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_LY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_MA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_OM");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_QA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_SA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_SD");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_SY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_TN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_YE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-be_BY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-bg_BG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-bn_BD");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-bn_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-bo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-bo_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-bo_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-br_FR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-bs_BA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ca_AD");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ca_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ca_ES_valencia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ca_FR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ca_IT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-cs_CZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-da_DK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-de_AT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-de_CH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-de_DE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-dictionaries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-el_GR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_AU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_BS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_BZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_CA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_GH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_JM");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_MW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_NA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_NZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_PH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_TT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_US");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_ZW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_AR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_BO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_CL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_CO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_CR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_CU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_DO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_EC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_GT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_HN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_MX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_NI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_PA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_PE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_PR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_PY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_SV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_UY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_VE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-et_EE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-fr_BE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-fr_CA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-fr_CH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-fr_FR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-fr_LU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-fr_MC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-gd_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-gl_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-gug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-gug_PY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-he_IL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-hi_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-hr_HR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-is_IS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-it_IT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-kmr_Latn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-kmr_Latn_SY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-kmr_Latn_TR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-lightproof-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-lightproof-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-lightproof-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-lightproof-ru_RU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-lo_LA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-lt_LT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-lv_LV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ne_NP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-nl_BE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-nl_NL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-oc_FR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-pl_PL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-pt_AO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ro_RO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ru_RU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-si_LK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sk_SK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sl_SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sr_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sr_Latn_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sr_Latn_RS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sr_RS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sv_FI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sv_SE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sw_TZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-te_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-th_TH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-uk_UA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-vi_VN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libixion-0_12-0-0.12.1-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libixion-0_12-0-debuginfo-0.12.1-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libixion-debugsource-0.12.1-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libixion-devel-0.12.1-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libixion-python3-0.12.1-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libixion-python3-debuginfo-0.12.1-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libixion-tools-0.12.1-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libixion-tools-debuginfo-0.12.1-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmwaw-0_3-3-0.3.11-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmwaw-0_3-3-debuginfo-0.3.11-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmwaw-debugsource-0.3.11-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmwaw-devel-0.3.11-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmwaw-tools-0.3.11-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmwaw-tools-debuginfo-0.3.11-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"liborcus-0_12-0-0.12.1-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"liborcus-0_12-0-debuginfo-0.12.1-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"liborcus-debugsource-0.12.1-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"liborcus-devel-0.12.1-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"liborcus-python3-0.12.1-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"liborcus-python3-debuginfo-0.12.1-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"liborcus-tools-0.12.1-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"liborcus-tools-debuginfo-0.12.1-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-branding-upstream-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-gdb-pretty-printers-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-glade-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-icon-theme-breeze-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-icon-theme-galaxy-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-icon-theme-hicontrast-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-icon-theme-oxygen-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-icon-theme-sifr-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-icon-theme-tango-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-af-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-ar-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-as-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-bg-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-bn-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-br-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-ca-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-cs-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-cy-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-da-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-de-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-dz-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-el-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-en-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-es-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-et-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-eu-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-fa-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-fi-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-fr-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-ga-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-gl-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-gu-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-he-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-hi-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-hr-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-hu-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-it-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-ja-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-kk-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-kn-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-ko-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-lt-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-lv-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-mai-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-ml-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-mr-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-nb-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-nl-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-nn-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-nr-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-nso-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-or-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-pa-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-pl-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-pt_BR-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-pt_PT-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-ro-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-ru-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-si-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-sk-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-sl-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-sr-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-ss-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-st-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-sv-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-ta-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-te-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-th-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-tn-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-tr-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-ts-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-uk-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-ve-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-xh-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-zh_CN-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-zh_TW-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreoffice-l10n-zu-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libstaroffice-0_0-0-0.0.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libstaroffice-0_0-0-debuginfo-0.0.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libstaroffice-debugsource-0.0.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libstaroffice-devel-0.0.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libstaroffice-tools-0.0.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libstaroffice-tools-debuginfo-0.0.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libzmf-0_0-0-0.0.1-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libzmf-0_0-0-debuginfo-0.0.1-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libzmf-debugsource-0.0.1-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libzmf-devel-0.0.1-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libzmf-tools-0.0.1-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libzmf-tools-debuginfo-0.0.1-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-af_NA-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-af_ZA-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-an-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-an_ES-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_AE-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_BH-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_DZ-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_EG-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_IQ-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_JO-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_KW-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_LB-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_LY-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_MA-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_OM-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_QA-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_SA-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_SD-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_SY-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_TN-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ar_YE-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-be_BY-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-bg_BG-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-bn_BD-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-bn_IN-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-bo-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-bo_CN-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-bo_IN-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-br_FR-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-bs-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-bs_BA-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ca-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ca_AD-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ca_ES-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ca_ES_valencia-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ca_FR-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ca_IT-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-cs_CZ-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-da_DK-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-de-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-de_AT-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-de_CH-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-de_DE-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-dictionaries-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-el_GR-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_AU-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_BS-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_BZ-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_CA-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_GB-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_GH-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_IE-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_IN-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_JM-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_MW-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_NA-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_NZ-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_PH-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_TT-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_US-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_ZA-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-en_ZW-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_AR-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_BO-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_CL-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_CO-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_CR-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_CU-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_DO-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_EC-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_ES-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_GT-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_HN-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_MX-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_NI-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_PA-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_PE-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_PR-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_PY-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_SV-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_UY-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-es_VE-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-et_EE-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-fr_BE-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-fr_CA-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-fr_CH-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-fr_FR-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-fr_LU-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-fr_MC-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-gd_GB-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-gl-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-gl_ES-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-gu_IN-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-gug-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-gug_PY-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-he_IL-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-hi_IN-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-hr_HR-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-hu_HU-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-is-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-is_IS-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-it_IT-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-kmr_Latn-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-kmr_Latn_SY-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-kmr_Latn_TR-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-lightproof-en-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-lightproof-hu_HU-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-lightproof-pt_BR-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-lightproof-ru_RU-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-lo_LA-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-lt_LT-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-lv_LV-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-nb_NO-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ne_NP-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-nl_BE-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-nl_NL-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-nn_NO-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-no-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-oc_FR-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-pl_PL-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-pt_AO-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-pt_BR-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-pt_PT-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ro-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ro_RO-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-ru_RU-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-si_LK-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-sk_SK-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-sl_SI-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-sr-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-sr_CS-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-sr_Latn_CS-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-sr_Latn_RS-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-sr_RS-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-sv_FI-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-sv_SE-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-sw_TZ-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-te-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-te_IN-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-th_TH-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-uk_UA-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-vi-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-vi_VN-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"myspell-zu_ZA-20170511-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-base-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-base-debuginfo-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-base-drivers-mysql-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-base-drivers-mysql-debuginfo-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-debuginfo-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-calc-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-calc-debuginfo-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-calc-extensions-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-debuginfo-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-debugsource-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-draw-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-draw-debuginfo-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-filters-optional-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-gnome-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-gnome-debuginfo-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-gtk3-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-gtk3-debuginfo-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-impress-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-impress-debuginfo-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-kde4-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-kde4-debuginfo-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-mailmerge-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-math-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-math-debuginfo-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-officebean-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-officebean-debuginfo-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-pyuno-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-pyuno-debuginfo-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-sdk-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-sdk-debuginfo-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-writer-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-writer-debuginfo-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreoffice-writer-extensions-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreofficekit-5.3.3.2-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreofficekit-devel-5.3.3.2-18.6.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libixion-0_12-0 / libixion-0_12-0-debuginfo / libixion-debugsource / etc");
}
