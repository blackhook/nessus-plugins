#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-368.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(134851);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/24");

  script_name(english:"openSUSE Security Update : texlive-filesystem (openSUSE-2020-368)");
  script_summary(english:"Check for the openSUSE-2020-368 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for texlive-filesystem fixes the following issues :

Security issues fixed :

  - Changed default user for ls-R files and font cache
    directories to user nobody (bsc#1159740) 

  - Switched to rm instead of safe-rm or safe-rmdir to avoid
    race conditions (bsc#1158910) .

  - Made cron script more failsafe (bsc#1150556)

Non-security issue fixed :

  - Refreshed font map files on update (bsc#1155381) 

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159740"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected texlive-filesystem packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-bibtexextra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-binextra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-fontsextra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-fontsrecommended");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-fontutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-formatsextra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-games");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-humanities");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langarabic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langchinese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langcjk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langcyrillic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langczechslovak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langenglish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langeuropean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langfrench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langgerman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langgreek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langitalian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langjapanese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langkorean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langother");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langpolish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langportuguese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-langspanish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-latexextra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-latexrecommended");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-luatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-mathscience");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-metapost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-music");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-pictures");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-plaingeneric");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-pstricks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-publishers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-collection-xetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-extratools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-scheme-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-scheme-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-scheme-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-scheme-gust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-scheme-infraonly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-scheme-medium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-scheme-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-scheme-small");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-scheme-tetex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

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



flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-basic-2017.135.svn41616-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-bibtexextra-2017.135.svn44385-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-binextra-2017.135.svn44515-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-context-2017.135.svn42330-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-fontsextra-2017.135.svn43356-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-fontsrecommended-2017.135.svn35830-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-fontutils-2017.135.svn37105-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-formatsextra-2017.135.svn44177-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-games-2017.135.svn42992-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-humanities-2017.135.svn42268-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langarabic-2017.135.svn44496-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langchinese-2017.135.svn42675-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langcjk-2017.135.svn43009-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langcyrillic-2017.135.svn44401-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langczechslovak-2017.135.svn32550-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langenglish-2017.135.svn43650-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langeuropean-2017.135.svn44414-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langfrench-2017.135.svn40375-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langgerman-2017.135.svn42045-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langgreek-2017.135.svn44192-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langitalian-2017.135.svn30372-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langjapanese-2017.135.svn44554-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langkorean-2017.135.svn42106-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langother-2017.135.svn44414-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langpolish-2017.135.svn44371-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langportuguese-2017.135.svn30962-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-langspanish-2017.135.svn40587-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-latex-2017.135.svn41614-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-latexextra-2017.135.svn44544-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-latexrecommended-2017.135.svn44177-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-luatex-2017.135.svn44500-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-mathscience-2017.135.svn44396-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-metapost-2017.135.svn44297-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-music-2017.135.svn40561-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-pictures-2017.135.svn44395-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-plaingeneric-2017.135.svn44177-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-pstricks-2017.135.svn44460-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-publishers-2017.135.svn44485-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-collection-xetex-2017.135.svn43059-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-devel-2017.135-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-extratools-2017.135-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-filesystem-2017.135-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-scheme-basic-2017.135.svn25923-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-scheme-context-2017.135.svn35799-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-scheme-full-2017.135.svn44177-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-scheme-gust-2017.135.svn44177-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-scheme-infraonly-2017.135.svn41515-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-scheme-medium-2017.135.svn44177-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-scheme-minimal-2017.135.svn13822-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-scheme-small-2017.135.svn41825-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"texlive-scheme-tetex-2017.135.svn44187-lp151.8.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "texlive-collection-basic / texlive-collection-bibtexextra / etc");
}
