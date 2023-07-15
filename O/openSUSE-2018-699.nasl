#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-699.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110957);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-1071", "CVE-2018-1083", "CVE-2018-1100");

  script_name(english:"openSUSE Security Update : zsh (openSUSE-2018-699)");
  script_summary(english:"Check for the openSUSE-2018-699 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for zsh to version 5.5 fixes the following issues :

Security issues fixed :

  - CVE-2018-1100: Fixes a buffer overflow in
    utils.c:checkmailpath() that can lead to local arbitrary
    code execution (bsc#1089030)

  - CVE-2018-1071: Fixed a stack-based buffer overflow in
    exec.c:hashcmd() (bsc#1084656)

  - CVE-2018-1083: Fixed a stack-based buffer overflow in
    gen_matches_files() at compctl.c (bsc#1087026)

Non-security issues fixed :

  - The effect of the NO_INTERACTIVE_COMMENTS option extends
    into $(...) and `...` command substitutions when used on
    the command line.

  - The 'exec' and 'command' precommand modifiers, and
    options to them, are now parsed after parameter
    expansion.

  - Functions executed by ZLE widgets no longer have their
    standard input closed, but redirected from /dev/null
    instead.

  - There is an option WARN_NESTED_VAR, a companion to the
    existing WARN_CREATE_GLOBAL that causes a warning if a
    function updates a variable from an enclosing scope
    without using typeset -g.

  - zmodload now has an option -s to be silent on a failure
    to find a module but still print other errors.

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089030"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected zsh packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zsh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zsh-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zsh-htmldoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"zsh-5.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"zsh-debuginfo-5.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"zsh-debugsource-5.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"zsh-htmldoc-5.5-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zsh / zsh-debuginfo / zsh-debugsource / zsh-htmldoc");
}
