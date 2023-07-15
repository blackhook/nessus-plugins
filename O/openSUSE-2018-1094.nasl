#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1094.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117898);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-0502", "CVE-2018-1071", "CVE-2018-1083", "CVE-2018-1100", "CVE-2018-13259");

  script_name(english:"openSUSE Security Update : zsh (openSUSE-2018-1094)");
  script_summary(english:"Check for the openSUSE-2018-1094 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for zsh to version 5.6.2 fixes the following issues :

These security issues were fixed :

  - CVE-2018-0502: The beginning of a #! script file was
    mishandled, potentially leading to an execve call to a
    program named on the second line (bsc#1107296)

  - CVE-2018-13259: Shebang lines exceeding 64 characters
    were truncated, potentially leading to an execve call to
    a program name that is a substring of the intended one
    (bsc#1107294)

  - CVE-2018-1100: Prevent stack-based buffer overflow in
    the utils.c:checkmailpath function that allowed local
    attackers to execute arbitrary code in the context of
    another user (bsc#1089030).

  - CVE-2018-1071: Prevent stack-based buffer overflow in
    the exec.c:hashcmd() function that allowed local
    attackers to cause a denial of service (bsc#1084656).

  - CVE-2018-1083: Prevent buffer overflow in the shell
    autocomplete functionality that allowed local
    unprivileged users to create a specially crafted
    directory path which lead to code execution in the
    context of the user who tries to use autocomplete to
    traverse the mentioned path (bsc#1087026).

  - Disallow evaluation of the initial values of integer
    variables imported from the environment

These non-security issues were fixed :

  - Fixed that the signal SIGWINCH was being ignored when
    zsh is not in the foreground.

  - Fixed two regressions with pipelines getting
    backgrounded and emitting the signal SIGTTOU

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

  - Fix typo in chflags completion

  - Fixed invalid git commands completion

  - VCS info system: vcs_info git: Avoid a fork.

  - Fix handling of 'printf -' and 'printf --'

  - fix broken completion for filterdiff (boo#1019130)

  - Unicode9 support, this needs support from your terminal
    to work correctly.

  - The new word modifier ':P' computes the physical path of
    the argument.

  - The output of 'typeset -p' uses 'export' commands or the
    '-g' option for parameters that are not local to the
    current scope.

  - vi-repeat-change can repeat user-defined widgets if the
    widget calls zle -f vichange.

  - The parameter $registers now makes the contents of vi
    register buffers available to user-defined widgets.

  - New vi-up-case and vi-down-case builtin widgets bound to
    gU/gu (or U/u in visual mode) for doing case conversion.

  - A new select-word-match function provides vim-style text
    objects with configurable word boundaries using the
    existing match-words-by-style mechanism.

  - Support for the conditional expression [[ -v var ]] to
    test if a variable is set for compatibility with other
    shells.

  - The print and printf builtins have a new option -v to
    assign the output to a variable.

  - New x: syntax in completion match specifications make it
    possible to disable match specifications hardcoded in
    completion functions.

  - Re-add custom zshrc and zshenv to unbreak compatibility
    with old usage (boo#998858).

  - Read /etc/profile as zsh again. 

  - The new module zsh/param/private can be loaded to allow
    the shell to define parameters that are private to a
    function scope (i.e. are not propagated to nested
    functions called within this function).

  - The GLOB_STAR_SHORT option allows the pattern **/* to be
    shortened to just ** if no / follows. so **.c searches
    recursively for a file whose name has the suffix '.c'.

  - The effect of the WARN_CREATE_GLOBAL option has been
    significantly extended, so expect it to cause additional
    warning messages about parameters created globally
    within function scope.

  - The print builtin has new options -x and -X to expand
    tabs.

  - Several new command completions and numerous updates to
    others.

  - Options to 'fc' to segregate internal and shared
    history.

  - All emulations including 'sh' use multibyte by default;
    several repairs to multibyte handling.

  - ZLE supports 'bracketed paste' mode to avoid
    interpreting pasted newlines as accept-line. Pastes can
    be highlighted for visibility and to make it more
    obvious whether accept-line has occurred.

  - Improved (though still not perfect) POSIX compatibility
    for getopts builtin when POSIX_BUILTINS is set.

  - New setopt APPEND_CREATE for POSIX-compatible NO_CLOBBER
    behavior.

  - Completion of date values now displays in a calendar
    format when the complist module is available.
    Controllable by zstyle.

  - New parameter UNDO_LIMIT_NO for more control over ZLE
    undo repeat.

  - Several repairs/improvements to the contributed
    narrow-to-region ZLE function.

  - Many changes to child-process and signal handling to
    eliminate race conditions and avoid deadlocks on
    descriptor and memory management.

  - New builtin sysopen in zsh/system module for detailed
    control of file descriptor modes. 

  - Fix a printf regression boo#934175 

  - Global aliases can be created for syntactic tokens such
    as command separators (';', '&', '|', '&&', '||'),
    redirection operators, etc.

  - There have been various further improvements to builtin
    handling with the POSIX_BUILTINS option (off by default)
    for compatibility with the POSIX standard.

  - 'whence -v' is now more informative, and 'whence -S'
    shows you how a full chain of symbolic links resolves to
    a command.

  - The 'p' parameter flag now allows an argument to be
    specified as a reference to a variable, e.g.
    $((ps.$sep.)foo) to split $foo on a string given by
    $sep.

  - The option FORCE_FLOAT now forces variables, not just
    constants, to floating point in arithmetic expressions.

  - The type of an assignment in arithmetic expressions,
    e.g. the type seen by the variable res in $(( res = a =
    b )), is now more logical and C-like.

  - The default binding of 'u' in vi command mode has
    changed to undo multiple changes when invoked
    repeatedly. '^R' is now bound to redo changes. To revert
    to toggling of the last edit use: bindkey -a u
    vi-undo-change

  - Compatibility with Vim has been improved for vi editing
    mode. Most notably, Vim style text objects are supported
    and the region can be manipulated with vi commands in
    the same manner as Vim's visual mode.

  - Elements of the watch variable may now be patterns.

  - The logic for retrying history locking has been
    improved.

  - Fix openSUSE versions in osc completion

  - Add back rpm completion file (boo#900424)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019130"
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=900424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=934175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=998858"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected zsh packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zsh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zsh-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zsh-htmldoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"zsh-5.6.2-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"zsh-debuginfo-5.6.2-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"zsh-debugsource-5.6.2-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"zsh-htmldoc-5.6.2-9.6.1") ) flag++;

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
