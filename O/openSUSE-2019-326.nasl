#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-326.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122848);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-12473", "CVE-2018-12474", "CVE-2018-12476");

  script_name(english:"openSUSE Security Update : obs-service-tar_scm (openSUSE-2019-326)");
  script_summary(english:"Check for the openSUSE-2019-326 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for obs-service-tar_scm fixes the following issues :

Security vulnerabilities addressed :

  - CVE-2018-12473: Fixed a path traversal issue, which
    allowed users to access files outside of the repository
    using relative paths (bsc#1105361)

  - CVE-2018-12474: Fixed an issue whereby crafted service
    parameters allowed for unexpected behaviour
    (bsc#1107507)

  - CVE-2018-12476: Fixed an issue whereby the outfilename
    parameter allowed to write files outside of package
    directory (bsc#1107944)

Other bug fixes and changes made :

  - Prefer UTF-8 locale as output format for changes

  - added KankuFile

  - fix problems with unicode source files

  - added python-six to Requires in specfile

  - better encoding handling

  - fixes bsc#1082696 and bsc#1076410

  - fix unicode in containers

  - move to python3

  - added logging for better debugging changesgenerate

  - raise exception if no changesauthor given

  - Stop using @opensuse.org addresses to indicate a missing
    address

  - move argparse dep to -common package

  - allow submodule and ssl options in appimage

  - sync spec file as used in openSUSE:Tools project

  - check encoding problems for svn and print proper error
    msg

  - added new param '--locale'

  - separate service file installation in GNUmakefile

  - added glibc as Recommends in spec file

  - cleanup for broken svn caches

  - another fix for unicode problem in obs_scm

  - Final fix for unicode in filenames

  - Another attempt to fix unicode filenames in
    prep_tree_for_archive

  - Another attempt to fix unicode filenames in
    prep_tree_for_archive

  - fix bug with unicode filenames in prep_tree_for_archive

  - reuse _service*_servicedata/changes files from previous
    service runs

  - fix problems with unicode characters in commit messages
    for changeloggenerate

  - fix encoding issues if commit message contains utf8 char

  - revert encoding for old changes file

  - remove hardcoded utf-8 encodings

  - Add support for extract globbing

  - split pylint2 in GNUmakefile

  - fix check for '--reproducible'

  - create reproducible obscpio archives

  - fix regression from 44b3bee

  - Support also SSH urls for Git

  - check name/version option in obsinfo for slashes

  - check url for remote url

  - check symlinks in subdir parameter

  - check filename for slashes

  - disable follow_symlinks in extract feature

  - switch to obs_scm for this package

  - run download_files in appimage and snapcraft case

  - check --extract file path for parent dir

  - Fix parameter descriptions

  - changed os.removedirs -> shutil.rmtree

  - Adding information regarding the *package-metadata*
    option for the *tar* service The tar service is highly
    useful in combination with the *obscpio* service. After
    the fix for the metadata for the latter one, it is
    important to inform the users of the *tar* service that
    metadata is kept only if the flag *package-metadata* is
    enabled. Add the flag to the .service file for
    mentioning that.

  - Allow metadata packing for CPIO archives when desired As
    of now, metadata are always excluded from *obscpio*
    packages. This is because the *package-metadata* flag is
    ignored; this change (should) make *obscpio* aware of
    it.

  - improve handling of corrupt git cache directories

  - only do git stash save/pop if we have a non-empty
    working tree (#228)

  - don't allow DEBUG_TAR_SCM to change behaviour (#240)

  - add stub user docs in lieu of something proper (#238)

  - Remove clone_dir if clone fails

  - python-unittest2 is only required for the optional make
    check

  - move python-unittest2 dep to test suite only part
    (submission by olh)

  - Removing redundant pass statement

  - missing import for logging functions.

  - [backend] Adding http proxy support

  - python-unittest2 is only required for the optional make
    check

  - make installation of scm's optional

  - add a lot more detail to README

  - Git clone with --no-checkout in prepare_working_copy

  - Refactor and simplify git prepare_working_copy

  - Only use current dir if it actually looks like git
    (Fixes #202)

  - reactivate test_obscpio_extract_d

  - fix broken test create_archive

  - fix broken tests for broken-links

  - changed PREFIX in Gnumakefile to /usr

  - new cli option --skip-cleanup

  - fix for broken links

  - fix reference to snapcraft YAML file

  - fix docstring typo in TarSCM.scm.tar.fetch_upstream

  - acknowledge deficiencies in dev docs

  - wrap long lines in README

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107944"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected obs-service-tar_scm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:obs-service-appimage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:obs-service-obs_scm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:obs-service-obs_scm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:obs-service-snapcraft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:obs-service-tar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:obs-service-tar_scm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"obs-service-appimage-0.10.5.1551309990.79898c7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"obs-service-obs_scm-0.10.5.1551309990.79898c7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"obs-service-obs_scm-common-0.10.5.1551309990.79898c7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"obs-service-snapcraft-0.10.5.1551309990.79898c7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"obs-service-tar-0.10.5.1551309990.79898c7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"obs-service-tar_scm-0.10.5.1551309990.79898c7-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "obs-service-appimage / obs-service-obs_scm / etc");
}
