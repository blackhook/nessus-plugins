#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1834.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(142506);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/20");

  script_cve_id("CVE-2018-19387", "CVE-2020-27347");

  script_name(english:"openSUSE Security Update : tmux (openSUSE-2020-1834)");
  script_summary(english:"Check for the openSUSE-2020-1834 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for tmux fixes the following issues :

  - Update to version 3.1c

  - Fix a stack overflow on colon-separated CSI parsing.
    boo#1178263 CVE-2020-27347

  - tmux 3.1b :

  - Fix crash when allow-rename ison and an empty name is
    set

  - tmux 3.1a :

  - Do not close stdout prematurely in control mode since it
    is needed to print exit messages. Prevents hanging when
    detaching with iTerm2

  - includes changes between 3.1-rc1 and 3.1 :

  - Only search the visible part of the history when marking
    (highlighting) search terms. This is much faster than
    searching the whole history and solves problems with
    large histories. The count of matches shown is now the
    visible matches rather than all matches

  - Search using regular expressions in copy mode.
    search-forward and search-backward use regular
    expressions by default; the incremental versions do not

  - Turn off mouse mode 1003 as well as the rest when
    exiting

  - Add selection_active format for when the selection is
    present but not moving with the cursor

  - Fix dragging with modifier keys, so binding keys such as
    C-MouseDrag1Pane and C-MouseDragEnd1Pane now work

  - Add -a to list-keys to also list keys without notes with
    -N

  - Do not jump to next word end if already on a word end
    when selecting a word; fixes select-word with single
    character words and vi(1) keys

  - Fix top and bottom pane calculation with pane border
    status enabled

  - Update to v3.1-rc

  - Please see the included CHANGES file

  - Fix tmux completion

  - Update to v3.0a

  - A lot of changes since v2.9a, please see the included
    CHANGES file.

  - Update to v2.9a

  - Fix bugs in select-pane and the main-horizontal and
    main-vertical layouts.

  - Add trailing newline to tmpfiles.d/tmux.conf. On newer
    systems (such as Leap 15.1), the lack of a trailing
    newline appears to cause the directory to not be
    created. This is only evident on setups where /run is an
    actual tmpfs (on btrfs-root installs, /run is a btrfs
    subvolume and thus /run/tmux is persistent across
    reboots).

  - Update to version 2.9

  - Add format variables for the default formats in the
    various modes (tree_mode_format and so on) and add a -a
    flag to display-message to list variables with values.

  - Add a -v flag to display-message to show verbose
    messages as the format is parsed, this allows formats to
    be debugged

  - Add support for HPA (\033[`).

  - Add support for origin mode (\033[?6h).

  - No longer clear history on RIS.

  - Extend the #[] style syntax and use that together with
    previous format changes to allow the status line to be
    entirely configured with a single option.

  - Add E: and T: format modifiers to expand a format twice
    (useful to expand the value of an option).

  - The individual -fg, -bg and -attr options have been
    removed; they were superseded by -style options in tmux
    1.9.

  - Add -b to display-panes like run-shell.

  - Handle UTF-8 in word-separators option.

  - New 'terminal' colour allowing options to use the
    terminal default colour rather than inheriting the
    default from a parent option.

  - Do not move the cursor in copy mode when the mouse wheel
    is used.

  - Use the same working directory rules for jobs as new
    windows rather than always starting in the user's home.

  - Allow panes to be one line or column in size.

  - Go to last line when goto-line number is out of range in
    copy mode.

  - Yank previously cut text if any with C-y in the command
    prompt, only use the buffer if no text has been cut.

  - Add q: format modifier to quote shell special
    characters.

  - Add -Z to find-window.

  - Support for windows larger than the client. This adds
    two new options, window-size and default-size, and a new
    command, resize-window. The force-width and force-height
    options and the session_width and session_height formats
    have been removed.

  - update to 2.8

  - move bash-completion to right place

  - Make display-panes block the client until a pane is
    chosen or it times out.

  - Clear history on RIS like most other terminals do.

  - Add an 'Any' key to run a command if a key is pressed
    that is not bound in the current key table.

  - Expand formats in load-buffer and save-buffer.

  - Add a rectangle_toggle format.

  - Add set-hook -R to run a hook immediately.

  - Add pane focus hooks.

  - Allow any punctuation as separator for s/x/y not only /.

  - Improve resizing with the mouse (fix resizing the wrong
    pane in some layouts, and allow resizing multiple panes
    at the same time).

  - Allow , and ) to be escaped in formats as #, and #).

  - Add KRB5CCNAME to update-environment.

  - Change meaning of -c to display-message so the client is
    used if it matches the session given to -t.

  - Fixes to : form of SGR.

  - Add x and X to choose-tree to kill sessions, windows or
    panes.

  - Add bash completion for tmux

  - Update to 2.7

  - Remove EVENT_* variables from environment on platforms
    where tmux uses them so they do not pass on to panes.

  - Fixed for hooks at server exit.

  - Remove SGR 10 (was equivalent to SGR 0 but no other
    terminal seems to do this).

  - Expand formats in window and session names.

  - Add -Z flag to choose-tree, choose-client, choose-buffer
    to automatically zoom the pane when the mode is entered
    and unzoom when it exits, assuming the pane is not
    already zoomed. This is now part of the default key
    bindings.

  - Add C-g to exit modes with emacs keys.

  - Add exit-empty option to exit server if no sessions
    (default = on)

  - Show if a filter is present in choose modes.

  - Add pipe-pane -I to to connect stdin of the child
    process.

  - Performance improvements for reflow.

  - Use RGB terminfo(5) capability to detect RGB colour
    terminals (the existing Tc extension remains unchanged).

  - Support for ISO colon-separated SGR sequences.

  - Add select-layout -E to spread panes out evenly (bound
    to E key).

  - Support wide characters properly when reflowing.

  - Pass PWD to new panes as a hint to shells, as well as
    calling chdir().

  - Performance improvements for the various choose modes.

  - Only show first member of session groups in tree mode
    (-G flag to choose-tree to show all).

  - Support %else in config files to match %if

  - Fix 'kind' terminfo(5) capability to be S-Down not S-Up.

  - Add a box around the preview label in tree mode.

  - Show exit status and time in the remain-on-exit pane
    text

  - Correctly use pane-base-index in tree mode.

  - Change the allow-rename option default to off.

  - Support for xterm(1) title stack escape sequences

  - Correctly remove padding cells to fix a UTF-8 display
    problem

  - build from release tarball instead of source (drops
    automake dep)

  - Bash completion is now removed and provided by

  - cleanup specfile directory with tmpfiles.d functionality
    in /run/tmux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178263"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tmux packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27347");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tmux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tmux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tmux-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1|SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1 / 15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"tmux-3.1c-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"tmux-debuginfo-3.1c-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"tmux-debugsource-3.1c-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tmux-3.1c-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tmux-debuginfo-3.1c-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tmux-debugsource-3.1c-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tmux / tmux-debuginfo / tmux-debugsource");
}
