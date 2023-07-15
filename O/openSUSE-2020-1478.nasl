#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1478.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(140690);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/23");

  script_cve_id("CVE-2020-24614");

  script_name(english:"openSUSE Security Update : fossil (openSUSE-2020-1478)");
  script_summary(english:"Check for the openSUSE-2020-1478 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for fossil fixes the following issues :

  - fossil 2.12.1 :

  - CVE-2020-24614: Remote authenticated users with check-in
    or administrative privileges could have executed
    arbitrary code [boo#1175760]

  - Security fix in the 'fossil git export' command. New
    'safety-net' features were added to prevent similar
    problems in the future.

  - Enhancements to the graph display for cases when there
    are many cherry-pick merges into a single check-in.
    Example

  - Enhance the fossil open command with the new --workdir
    option and the ability to accept a URL as the repository
    name, causing the remote repository to be cloned
    automatically. Do not allow 'fossil open' to open in a
    non-empty working directory unless the --keep option or
    the new --force option is used.

  - Enhance the markdown formatter to more closely follow
    the CommonMark specification with regard to text
    highlighting. Underscores in the middle of identifiers
    (ex: fossil_printf()) no longer need to be escaped.

  - The markdown-to-html translator can prevent unsafe HTML
    (for example: <script>) on user-contributed pages like
    forum and tickets and wiki. The admin can adjust this
    behavior using the safe-html setting on the Admin/Wiki
    page. The default is to disallow unsafe HTML everywhere.

  - Added the 'collapse' and 'expand' capability for long
    forum posts.

  - The 'fossil remote' command now has options for
    specifying multiple persistent remotes with symbolic
    names. Currently only one remote can be used at a time,
    but that might change in the future.

  - Add the 'Remember me?' checkbox on the login page. Use a
    session cookie for the login if it is not checked.

  - Added the experimental 'fossil hook' command for
    managing 'hook scripts' that run before checkin or after
    a push.

  - Enhance the fossil revert command so that it is able to
    revert all files beneath a directory.

  - Add the fossil bisect skip command.

  - Add the fossil backup command.

  - Enhance fossil bisect ui so that it shows all unchecked
    check-ins in between the innermost 'good' and 'bad'
    check-ins.

  - Added the --reset flag to the 'fossil add', 'fossil rm',
    and 'fossil addremove' commands.

  - Added the '--min N' and '--logfile FILENAME' flags to
    the backoffice command, as well as other enhancements to
    make the backoffice command a viable replacement for
    automatic backoffice. Other incremental backoffice
    improvements.

  - Added the /fileedit page, which allows editing of text
    files online. Requires explicit activation by a setup
    user.

  - Translate built-in help text into HTML for display on
    web pages.

  - On the /timeline webpage, the combination of query
    parameters 'p=CHECKIN' and 'bt=ANCESTOR' draws all
    ancestors of CHECKIN going back to ANCESTOR.

  - Update the built-in SQLite so that the 'fossil sql'
    command supports new output modes '.mode box' and '.mode
    json'.

  - Add the 'obscure()' SQL function to the 'fossil sql'
    command.

  - Added virtual tables 'helptext' and 'builtin' to the
    'fossil sql' command, providing access to the dispatch
    table including all help text, and the builtin data
    files, respectively.

  - Delta compression is now applied to forum edits.

  - The wiki editor has been modernized and is now
    Ajax-based.

  - Package the fossil.1 manual page.

  - fossil 2.11.1 :

  - Make the 'fossil git export' command more restrictive
    about characters that it allows in the tag names

  - Add fossil-2.11-reproducible.patch to override build
    date (boo#1047218)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175760"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected fossil packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fossil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fossil-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fossil-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/21");
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

if ( rpm_check(release:"SUSE15.1", reference:"fossil-2.12.1-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"fossil-debuginfo-2.12.1-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"fossil-debugsource-2.12.1-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fossil-2.12.1-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fossil-debuginfo-2.12.1-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fossil-debugsource-2.12.1-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fossil / fossil-debuginfo / fossil-debugsource");
}
