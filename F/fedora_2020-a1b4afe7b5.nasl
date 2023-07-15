#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-a1b4afe7b5.
#

include("compat.inc");

if (description)
{
  script_id(133014);
  script_version("1.1");
  script_cvs_date("Date: 2020/01/17");

  script_xref(name:"FEDORA", value:"2020-a1b4afe7b5");

  script_name(english:"Fedora 31 : phpMyAdmin (2020-a1b4afe7b5)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Version 5.0.1** (2020-01-07)

  - issue #15719 Fixed error 500 when browsing a table when
    $cfg['LimitChars'] used a string and not an int value

  - issue #14936 Fixed display NULL on numeric fields has
    showing empty string since 5.0.0

  - issue #15722 Fix get Database structure fails with PHP
    error on replicated server

  - issue #15723 Fix can't browse certain tables since 5.0.0
    update

  - issue Prevent line wrap in DB structure size column

  - issue Remove extra line break from downloaded blob
    content

  - issue #15725 Fixed error 500 when exporting - set time
    limit when $cfg['ExecTimeLimit'] used a string and not
    an int value

  - issue #15726 Fixed double delete icons on enum editor

  - issue #15717 Fixed warning popup not dissapearing on
    table stucture when using actions without any column
    selection

  - issue #15693 Fixed focus of active tab is lost by
    clicking refresh option on browse tab

  - issue #15734 Fix Uncaught TypeError: http_build_query()
    in setup

  - issue Fix double slash in path when $cfg['TempDir'] has
    a trailing slash

  - issue #14875 Fix shp file import tests where failing
    when php dbase extension was enabled

  - issue #14299 Fix JS error 'PMA_makegrid is not defined'
    when clicking on a table from the 'Insert' tab opened in
    a new tab

  - issue #15351 Fixed 2FA setting removed each time the
    user edits another configuration setting

  - issue [security] Fix SQL injection vulnerability on the
    user accounts page (PMASA-2020-1)

----

**Welcome to the release of phpMyAdmin version 5.0.0.**

This release includes many new features and improvements from the 4.9
series. We expect to maintain version 4 in a security capacity to
support users with older PHP installations.

With this release, we are removing support of old PHP versions (5.5,
5.6, 7.0, and HHVM). These versions are outdated and are no longer
supported by the PHP team.

Version 5.0 includes many coding improvements that modernize the
interface. Many of these changes are transparent to users, but make
the code easier to maintain. Much of this refactoring work is
completed by our contract developer, Maur&iacute;cio Meneghini Fauth.

Some of the changes and new features include :

  - Enable columns names by default for CSV exports

  - Add Metro theme

  - Automatically add the index when creating an auto
    increment column

  - Improvements to exporting views

  - Prompt the user for confirmation before running an
    UPDATE query with no WHERE clause

  - Improvements to how errors are show to the user
    (including allowing easier copying of the error text to
    the clipboard)

  - Added keystrokes to clear the line (ctrl+l) and clear
    the entire console window (ctrl+u)

  - Use charset 'windows-1252' when export format is MS
    Excel

There are several more changes, please refer to the ChangeLog file
included with the release for full details.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-a1b4afe7b5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^31([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 31", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC31", reference:"phpMyAdmin-5.0.1-1.fc31")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
