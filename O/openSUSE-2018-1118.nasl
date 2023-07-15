#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1118.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117978);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-16976");

  script_name(english:"openSUSE Security Update : gitolite (openSUSE-2018-1118)");
  script_summary(english:"Check for the openSUSE-2018-1118 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gitolite fixes the following issues :

Gitolite was updated to 3.6.9 :

  - CVE-2018-16976: prevent racy access to repos in process
    of migration to gitolite (boo#1108272)

  - 'info' learns new '-p' option to show only physical
    repos (as opposed to wild repos)

The update to 3.6.8 contains :

  - fix bug when deleting *all* hooks for a repo

  - allow trailing slashes in repo names

  - make pre-receive hook driver bail on non-zero exit of a
    pre-receive hook

  - allow templates in gitolite.conf (new feature)

  - various optimiations

The update to 3.6.7 contains :

  - allow repo-specific hooks to be organised into
    subdirectories, and allow the multi-hook driver to be
    placed in some other location of your choice

  - allow simple test code to be embedded within the
    gitolite.conf file; see contrib/utils/testconf for how.
    (This goes on the client side, not on the server)

  - allow syslog 'facility' to be changed, from the default
    of 'local0'

  - allow syslog 'facility' to be changed, from the default
    of replaced with a space separated list of members

The update to 3.6.6 contains :

  - simple but important fix for a future perl deprecation
    (perl will be removing '.' from @INC in 5.24)

  - 'perms' now requires a '-c' to activate batch mode
    (should not affect interactive use but check your
    scripts perhaps?)

  - gitolite setup now accepts a '-m' option to supply a
    custom message (useful when it is used by a script)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108272"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gitolite package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gitolite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"gitolite-3.6.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gitolite-3.6.9-4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gitolite");
}
