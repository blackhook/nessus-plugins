#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-c713d12577
#

include('compat.inc');

if (description)
{
  script_id(171581);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");
  script_xref(name:"FEDORA", value:"2023-c713d12577");

  script_name(english:"Fedora 36 : phpMyAdmin (2023-c713d12577)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 36 host has a package installed that is affected by a vulnerability as referenced in the
FEDORA-2023-c713d12577 advisory.

  - **phpMyAdmin 5.2.1**   This is a bugfix release that also contains a security fix for an XSS vulnerability
    in the drag-and-drop upload functionality (**PMASA-2023-01**).  Changelog:  - issue #17522 Fix case where
    the routes cache file is invalid - issue #17506 Fix error when configuring 2FA without XMLWriter or
    Imagick - issue        Fix blank page when some error occurs - issue #17519 Fix Export pages not working
    in certain conditions - issue #17496 Fix error in table operation page when partitions are broken - issue
    #17386 Fix system memory and system swap values on Windows - issue #17517 Fix Database Server panel not
    getting hidden by ShowServerInfo configuration directive - issue #17271 Fix database names not showing on
    Processes tab - issue #17424 Fix export limit size calculation - issue #17366 Fix refresh rate popup on
    Monitor page - issue #17577 Fix monitor charts size on RTL languages - issue #17121 Fix password_hash
    function incorrectly adding single quotes to password before hashing - issue #17586 Fix statistics not
    showing for empty databases - issue #17592 Clicking on the New index link on the sidebar does not throw an
    error anymore - issue #17584 It's now possible to browse a database that includes two % in its name -
    issue        Fix PHP 8.2 deprecated string interpolation syntax - issue        Some languages are now
    correctly detected from the HTTP header - issue #17617 Sorting is correctly remembered when
    $cfg['RememberSorting'] is true - issue #17593 Table filtering now works when action buttons are on the
    right side of the row - issue #17388 Find and Replace using regex now makes a valid query if no matching
    result set found - issue #17551 Enum/Set editor will not fail to open when creating a new column - issue
    #17659 Fix error when a database group is named tables, views, functions, procedures or events - issue
    #17673 Allow empty values to be inserted into columns - issue #17620 Fix error handling at phpMyAdmin
    startup for the JS SQL console - issue        Fixed debug queries console broken UI for query time and
    group count - issue        Fixed escaping of SQL query and errors for the debug console - issue        Fix
    console toolbar UI when the bookmark feature is disabled and sql debug is enabled - issue #17543 Fix JS
    error on saving a new designer page - issue #17546 Fix JS error after using save as and open page
    operation on the designer - issue        Fix PHP warning on GIS visualization when there is only one GIS
    column - issue #17728 Some select HTML tags will now have the correct UI style - issue #17734 PHP
    deprecations will only be shown when in a development environment - issue #17369 Fix server error when
    blowfish_secret is not exactly 32 bytes long - issue #17736 Add utf8mb3 as an alias of utf8 on the charset
    description page - issue #16418 Fix FAQ 1.44 about manually removing vendor folders - issue #12359 Setup
    page now sends the Content-Security-Policy headers - issue #17747 The Column Visibility Toggle will not be
    hidden by other elements - issue #17756 Edit/Copy/Delete row now works when using GROUP BY - issue #17248
    Support the UUID data type for MariaDB >= 10.7 - issue #17656 Fix replace/change/set table prefix is not
    working - issue        Fix monitor page filter queries only filtering the first row - issue        Fix
    Link not found! on foreign columns for tables having no char column to show - issue #17390 Fix Create
    view modal doesn't show on results and empty results - issue #17772 Fix wrong styles for add button from
    central columns - issue #17389 Fix HTML disappears when exporting settings to browser's storage - issue
    #17166 Fix Warning: #1287 'X' is deprecated [...] Please use ST_X instead. on search page - issue
    Use jquery-migrate.min.js (14KB) instead of jquery-migrate.min.js (31KB) - issue #17842 Use
    jquery.validate.min.js (24 KB) instead of jquery.validate.js (50 KB) - issue #17281 Fix links to databases
    for information_schema.SCHEMATA - issue #17553 Fix Metro theme unreadable links above navigation tree -
    issue #17553 Metro theme UI fixes and improvements - issue #17553 Fix Metro theme login form with - issue
    #16042 Exported gzip file of database has first ~73 kB uncompressed and rest is gzip compressed in Firefox
    - issue #17705 Fix inline SQL query edit FK checkbox preventing submit buttons from working - issue #17777
    Fix Uncaught TypeError: Cannot read properties of null (reading 'inline') on datepickers when re-opened -
    issue        Fix Original theme buttons style and login form width - issue #17892 Fix closing index edit
    modal and reopening causes it to fire twice - issue #17606 Fix preview SQL modal not working inside Add
    Index modal - issue        Fix PHP error on adding new column on create table form - issue #17482 Default
    to Full texts when running explain statements - issue        Fixed Chrome scrolling performance issue on
    a textarea of an export as text page - issue #17703 Fix datepicker appears on all fields, not just date
    - issue        Fix space in the tree line when a DB is expanded - issue #17340 Fix New Table page ->
    VIRTUAL attribute is lost when adding a new column - issue #17446 Fix missing option for STORED virtual
    column on MySQL and PERSISTENT is not supported on MySQL - issue #17446 Lower the check for virtual
    columns to MySQL>=5.7.6 nothing is supported on 5.7.5 - issue        Fix column names option for CSV
    Export - issue #17177 Fix preview SQL when reordering columns doesn't work on move columns - issue #15887
    Fixed DROP TABLE errors ignored on multi table select for DROP - issue #17944 Fix unable to create a view
    from tree view button - issue #17927 Fix key navigation between select inputs (drop an old Firefox
    workaround) - issue #17967 Fix missing icon for collapse all button - issue #18006 Fixed UUID columns
    can't be moved - issue        Add `spellcheck=false` to all password fields and some text fields to
    avoid spell-jacking data leaks - issue        Remove non working Analyze Explain at MariaDB.org button
    (MariaDB stopped this service) - issue #17229 Add support for Web Authentication API because Chrome
    removed support for the U2F API - issue #18019 Fix Call to a member function fetchAssoc() on bool with
    SQL mode ONLY_FULL_GROUP_BY on monitor search logs - issue        Add back UUID and UUID_SHORT to
    functions on MySQL and all MariaDB versions - issue #17398 Fix clicking on JSON columns triggers update
    query - issue        Fix silent JSON parse error on upload progress - issue #17833 Fix Add Parameter
    button not working for Add Routine Screen - issue #17365 Fixed Uncaught Error: regexp too big on server
    status variables page - issue        [security] Fix an XSS attack through the drag-and-drop upload feature
    (PMASA-2023-01)  (FEDORA-2023-c713d12577)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-c713d12577");
  script_set_attribute(attribute:"solution", value:
"Update the affected phpMyAdmin package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^36([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 36', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'phpMyAdmin-5.2.1-1.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'phpMyAdmin');
}
