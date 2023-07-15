#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1929.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(128014);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/23");

  script_cve_id("CVE-2018-16858");

  script_name(english:"openSUSE Security Update : LibreOffice (openSUSE-2019-1929)");
  script_summary(english:"Check for the openSUSE-2019-1929 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libreoffice and libraries fixes the following issues :

LibreOffice was updated to 6.2.5.2 (fate#327121 bsc#1128845
bsc#1123455), bringing lots of bug and stability fixes.

Additional bugfixes :

  - If there is no firebird engine we still need java to run
    hsqldb (bsc#1135189)

  - PPTX: Rectangle turns from green to blue and loses
    transparency when transparency is set (bsc#1135228)

  - Slide deck compression doesn't, hmm, compress too much
    (bsc#1127760)

  - Psychedelic graphics in LibreOffice (but not PowerPoint)
    (bsc#1124869)

  - Image from PPTX shown in a square, not a circle
    (bsc#1121874)

libixion was updated to 0.14.1 :

  - Updated for new orcus

liborcus was updated to 0.14.1 :

  - Boost 1.67 support

  - Various cell handling issues fixed

libwps was updated to 0.4.10 :

  - QuattroPro: add parser of .qwp files

  - all: support complex encoding

mdds was updated to 1.4.3 :

  - Api change to 1.4

  - More multivector operations and tweaks

  - Various multi vector fixes

  - flat_segment_tree: add segment iterator and functions

  - fix to handle out-of-range insertions on
    flat_segment_tree

  - Another api version -> rename to mdds-1_2

myspell-dictionaries was updated to 20190423 :

  - Serbian dictionary updated

  - Update af_ZA hunspell

  - Update Spanish dictionary

  - Update Slovenian dictionary

  - Update Breton dictionary

  - Update Galician dictionary

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/327121"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected LibreOffice packages."
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-0_14-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-0_14-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-0_14-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-0_14-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-firebird-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gtk2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-themes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bn_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-brx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ca_valencia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-dgo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-en_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kmr_Latn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kok");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-om");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sw_TZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-vec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-vi");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-qt5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-sdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreofficekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreofficekit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-0_4-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-0_4-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mdds-1_4-devel");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-id_ID");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sq_AL");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-tr_TR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-uk_UA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-vi_VN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-libixion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-libixion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-liborcus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-liborcus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-branding-upstream-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-gdb-pretty-printers-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-glade-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-icon-themes-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-af-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-am-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ar-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-as-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ast-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-be-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-bg-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-bn-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-bn_IN-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-bo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-br-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-brx-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-bs-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ca-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ca_valencia-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-cs-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-cy-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-da-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-de-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-dgo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-dsb-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-dz-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-el-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-en-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-en_GB-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-en_ZA-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-eo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-es-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-et-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-eu-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-fa-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-fi-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-fr-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-fy-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ga-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-gd-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-gl-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-gu-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-gug-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-he-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-hi-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-hr-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-hsb-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-hu-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-id-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-is-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-it-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ja-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ka-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-kab-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-kk-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-km-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-kmr_Latn-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-kn-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ko-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-kok-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ks-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-lb-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-lo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-lt-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-lv-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-mai-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-mk-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ml-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-mn-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-mni-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-mr-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-my-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-nb-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ne-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-nl-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-nn-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-nr-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-nso-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-oc-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-om-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-or-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-pa-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-pl-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-pt_BR-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-pt_PT-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ro-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ru-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-rw-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-sa_IN-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-sat-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-sd-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-si-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-sid-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-sk-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-sl-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-sq-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-sr-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ss-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-st-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-sv-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-sw_TZ-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ta-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-te-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-tg-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-th-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-tn-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-tr-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ts-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-tt-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ug-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-uk-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-uz-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-ve-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-vec-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-vi-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-xh-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-zh_CN-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-zh_TW-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libreoffice-l10n-zu-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mdds-1_4-devel-1.4.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-af_NA-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-af_ZA-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-an-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-an_ES-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_AE-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_BH-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_DZ-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_EG-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_IQ-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_JO-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_KW-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_LB-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_LY-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_MA-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_OM-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_QA-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_SA-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_SD-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_SY-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_TN-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ar_YE-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-be_BY-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-bg_BG-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-bn_BD-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-bn_IN-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-bo-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-bo_CN-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-bo_IN-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-br_FR-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-bs-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-bs_BA-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ca-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ca_AD-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ca_ES-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ca_ES_valencia-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ca_FR-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ca_IT-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-cs_CZ-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-da_DK-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-de-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-de_AT-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-de_CH-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-de_DE-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-dictionaries-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-el_GR-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_AU-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_BS-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_BZ-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_CA-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_GB-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_GH-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_IE-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_IN-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_JM-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_MW-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_NA-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_NZ-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_PH-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_TT-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_US-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_ZA-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-en_ZW-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_AR-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_BO-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_CL-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_CO-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_CR-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_CU-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_DO-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_EC-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_ES-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_GT-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_HN-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_MX-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_NI-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_PA-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_PE-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_PR-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_PY-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_SV-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_UY-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-es_VE-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-et_EE-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-fr_BE-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-fr_CA-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-fr_CH-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-fr_FR-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-fr_LU-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-fr_MC-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-gd_GB-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-gl-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-gl_ES-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-gu_IN-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-gug-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-gug_PY-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-he_IL-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-hi_IN-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-hr_HR-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-hu_HU-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-id-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-id_ID-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-is-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-is_IS-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-it_IT-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-kmr_Latn-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-kmr_Latn_SY-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-kmr_Latn_TR-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-lightproof-en-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-lightproof-hu_HU-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-lightproof-pt_BR-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-lightproof-ru_RU-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-lo_LA-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-lt_LT-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-lv_LV-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-nb_NO-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ne_NP-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-nl_BE-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-nl_NL-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-nn_NO-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-no-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-oc_FR-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-pl_PL-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-pt_AO-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-pt_BR-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-pt_PT-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ro-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ro_RO-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-ru_RU-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-si_LK-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-sk_SK-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-sl_SI-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-sq_AL-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-sr-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-sr_CS-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-sr_Latn_CS-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-sr_Latn_RS-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-sr_RS-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-sv_FI-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-sv_SE-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-sw_TZ-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-te-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-te_IN-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-th_TH-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-tr-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-tr_TR-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-uk_UA-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-vi-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-vi_VN-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"myspell-zu_ZA-20190423-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libixion-0_14-0-0.14.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libixion-0_14-0-debuginfo-0.14.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libixion-debuginfo-0.14.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libixion-debugsource-0.14.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libixion-devel-0.14.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libixion-tools-0.14.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libixion-tools-debuginfo-0.14.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"liborcus-0_14-0-0.14.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"liborcus-0_14-0-debuginfo-0.14.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"liborcus-debuginfo-0.14.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"liborcus-debugsource-0.14.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"liborcus-devel-0.14.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"liborcus-tools-0.14.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"liborcus-tools-debuginfo-0.14.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-base-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-base-debuginfo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-base-drivers-firebird-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-base-drivers-firebird-debuginfo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-debuginfo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-calc-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-calc-debuginfo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-calc-extensions-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-debuginfo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-debugsource-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-draw-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-draw-debuginfo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-filters-optional-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-gnome-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-gnome-debuginfo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-gtk2-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-gtk2-debuginfo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-gtk3-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-gtk3-debuginfo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-impress-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-impress-debuginfo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-mailmerge-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-math-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-math-debuginfo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-officebean-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-officebean-debuginfo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-pyuno-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-pyuno-debuginfo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-qt5-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-qt5-debuginfo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-sdk-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-sdk-debuginfo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-writer-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-writer-debuginfo-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreoffice-writer-extensions-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreofficekit-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libreofficekit-devel-6.2.5.2-lp151.3.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libwps-0_4-4-0.4.10-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libwps-0_4-4-debuginfo-0.4.10-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libwps-debuginfo-0.4.10-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libwps-debugsource-0.4.10-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libwps-devel-0.4.10-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libwps-tools-0.4.10-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libwps-tools-debuginfo-0.4.10-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"python3-libixion-0.14.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"python3-libixion-debuginfo-0.14.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"python3-liborcus-0.14.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"python3-liborcus-debuginfo-0.14.1-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libixion-0_14-0 / libixion-0_14-0-debuginfo / libixion-debuginfo / etc");
}
