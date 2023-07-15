#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-4e78c86902.
#

include("compat.inc");

if (description)
{
  script_id(141555);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/28");

  script_cve_id("CVE-2020-26934", "CVE-2020-26935");
  script_xref(name:"FEDORA", value:"2020-4e78c86902");

  script_name(english:"Fedora 32 : phpMyAdmin (2020-4e78c86902)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"**Version 5.0.3** (2020-10-09)

  - issue #15983 Require twig ^2.9

  - issue Fix option to import files locally appearing as
    not available

  - issue #16048 Fix to allow NULL as a default bit value

  - issue #16062 Fix 'htmlspecialchars() expects parameter 1
    to be string, null given' on Export xml

  - issue #16078 Fix no charts in monitor when using a
    decimal separator ','

  - issue #16041 Fix IN(...) clause doesn't permit multiple
    values on 'Search' page

  - issue #14411 Support double tap to edit on mobile

  - issue #16043 Fix php error 'Use of undefined constant
    MYSQLI_TYPE_JSON' when using the mysqlnd extension

  - issue #14611 Fix fatal JS error on index creation after
    using Enter key to submit the form

  - issue #16012 Set 'axis-order' to swap lon and lat on
    MySQL >= 8.1

  - issue #16104 Fixed overwriting a bookmarked query causes
    a PHP fatal error

  - issue Fix typo in a condition in the Sql class

  - issue #15996 Fix local setup doc links pointing to a
    wrong location

  - issue #16093 Fix error importing utf-8 with bom sql file

  - issue #16089 2FA UX enhancement: autofocus 2FA input

  - issue #16127 Fix table column description PHP error when
    ['DisableIS'] = true;

  - issue #16130 Fix local documentation links display when
    a PHP extension is missing

  - issue Fix some twig code deprecations for php 8

  - issue Fix ENUM and SET display when editing procedures
    and functions

  - issue Keep full query state on 'auto refresh' process
    list

  - issue Keep columns order on 'auto refresh' process list

  - issue Fixed editing a failed query from the error
    message

  - issue #16166 Fix the alter user privileges query to make
    it MySQL 8.0.11+ compatible

  - issue Fix copy table to another database when the nbr of
    DBs is > $cfg['MaxDbList']

  - issue #16157 Fix relations of tables having spaces or
    special chars not showing in the Designer

  - issue #16052 Fix a very rare JS error occuring on
    mousemove event

  - issue #16162 Make a foreign key link clickable in a new
    tab after the value was saved and replaced

  - issue #16163 Fixed a PHP notice 'Undefined index:
    column_info' on views

  - issue #14478 Fix the data stream when exporting data in
    file mode

  - issue #16184 Fix templates/ directory not found error

  - issue #16184 Remove chdir logic to fix PHP fatal error
    'Uncaught TypeError: chdir()'

  - issue Support for Twig 3

  - issue Allow phpmyadmin/twig-i18n-extension ^3.0

  - issue #16201 Trim spaces for integer values in table
    search

  - issue #16076 Fixed cannot edit or export TIMESTAMP
    column with default CURRENT_TIMESTAMP in MySQL >= 8.0.13

  - issue #16226 Fix error 500 after copying a table

  - issue #16222 Fixed can't use the search page when the
    table name has special characters

  - issue #16248 Fix zoom search is not performing input
    validation on INT columns

  - issue #16248 Fix JavaScript error when typing in INT
    fields on zoom search page

  - issue Fix type errors when using saved searches

  - issue #16261 Fix missing headings on modals of 'User
    Accounts -> Export'

  - issue #16146 Fixed sorting did not keep the selector of
    number of rows

  - issue #16194 Fixed SQL query does not appear in case of
    editing view where definer is not you on MySQL 8

  - issue #16255 Fix tinyint(1) shown as INT on Search page

  - issue #16256 Fix 'Warning: error_reporting() has been
    disabled for security reasons' on php 7.x

  - issue #15367 Fix 'Change or reconfigure primary server'
    link

  - issue #15367 Fix first replica links, start, stop,
    ignore links

  - issue #16058 Add 'PMA_single_signon_HMAC_secret' for
    signon auths to make special links work and udate
    examples

  - issue #16269 Support ReCaptcha v2 checkbox width
    '$cfg['CaptchaMethod'] = 'checkbox';'

  - issue #14644 Use Doctum instead of Sami

  - issue #16086 Fix 'Browse' headings shift when scrolling

  - issue #15328 Fix no message after import of zipped
    shapefile without php-zip

  - issue #14326 Fix PHP error when exporting without
    php-zip

  - issue #16318 Fix Profiling doesn't sum the number of
    calls

  - issue #16319 Fixed a Russian translation mistake on
    search results total text

  - issue #15634 Only use session_set_cookie_params once on
    PHP >= 7.3.0 versions for single signon auth

  - issue #14698 Fixed database named as 'New' (language
    variable) causes PHP fatal error

  - issue #16355 Make textareas both sides resizable

  - issue #16366 Fix column definition form not showing
    default value

  - issue #16342 Fixed multi-table query
    (db_multi_table_query.php) alias show the same alias for
    all columns

  - issue #15109 Fixed using ST_GeomFromText + GUI on insert
    throws an error

  - issue #16325 Fixed editing Geometry data throws error on
    using the GUI

  - issue [security] Fix XSS vulnerability with the
    transformation feature (**PMASA-2020-5,
    CVE-2020-26934**)

  - issue [security] Fix SQL injection vulnerability with
    search feature (**PMASA-2020-6, CVE-2020-26935**)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-4e78c86902"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26935");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:32");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");
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
if (! preg(pattern:"^32([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 32", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC32", reference:"phpMyAdmin-5.0.3-1.fc32")) flag++;


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
