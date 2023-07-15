#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-4917943339.
#

include("compat.inc");

if (description)
{
  script_id(132646);
  script_version("1.1");
  script_cvs_date("Date: 2020/01/06");

  script_xref(name:"FEDORA", value:"2019-4917943339");

  script_name(english:"Fedora 31 : drupal7 (2019-4917943339)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"RPM notes :

  - All docs are now in `/usr/share/doc/drupal7/`

  - All licenses are now in `/usr/share/licenses/drupal7/`

  - Requires have been updated to include all
    [phpcompatinfo](http://php5.laurent-laville.org/compatin
    fo/) extension findings

### 7.69

Maintenance and security release of the Drupal 7 series.

This release fixes **security vulnerabilities**. Sites are **[urged to
upgrade
immediately](https://www.drupal.org/docs/7/update/introduction)**
after reading the notes below and the security announcement :

  - [Drupal core - Critical - Multiple vulnerabilities -
    SA-CORE-2019-012](https://www.drupal.org/sa-core-2019-01
    2)

No other fixes are included.

#### Important update information

  - Drupal 7 includes a bundled version of the
    pear/archive_tar project, the included version has been
    updated from 1.4.5 to 1.4.9 in order to mitigate [Drupal
    core - Critical - Multiple vulnerabilities -
    SA-CORE-2019-012](https://www.drupal.org/sa-core-2019-01
    2)

No changes have been made to the `.htaccess`, `web.config`,
`robots.txt`, or default `settings.php` files in this release, so
upgrading custom versions of those files is not necessary.

### 7.68

Maintenance release of the Drupal 7 series. Includes bug fixes and
small API/feature improvements only (no major,
non-backwards-compatible new functionality).

No security fixes are included in this release.

**This is the first release to fully support PHP 7.3. Please test and
report any bugs in the issue queue.**

No changes have been made to robots.txt in this release, so upgrading
custom versions of that file is not necessary.

However, changes have been made to .htaccess, web.config and
sites/default/default.settings.php in this release.

The .htaccess and web.config changes are detailed in this Change
Record :

  - Access to web.config is blocked in .htaccess (and
    vice-versa): https://www.drupal.org/node/3098687

Upgrading custom versions of .htaccess and web.config to incorporate
this change is recommended, but not required.

There is one change to the sites/default/default.settings.php file in
this release, but the only change is to file permissions :

  - [Regression] Fix default.settings.php permission:
    https://www.drupal.org/node/3035772

#### Major changes since 7.67

  - Fully support PHP 7.3

  - drupal_http_request() accepts data as an array in Drupal
    7

  - Access to web.config is blocked in .htaccess (and
    vice-versa)

  - New 'scripts' element

  - theme_table() takes an optional footer variable and
    produces <tfoot>

#### All changes since 7.67

  - \#3098664 by mcdruid: drupal_http_build_query() only
    accepts arrays (followup to #3059391)

  - \#3097342 by mcdruid, Fabianx: Prepare Drupal 7.68
    (CHANGELOG.txt)

  - \#3088938 by DamienMcKenna, webchick, mcdruid: Update
    the D7 maintainers list

  - \#2902430 by stefanos.petrakis, joseph.olstad,
    SergFromSD, kiamlaluno, Ayesh, mcdruid, alexpott: [PHP
    7.1] A non-numeric value encountered in theme_pager()

  - \#2472025 by stupiddingo, stefanos.petrakis: [D7] Hide
    toolbar when printing

  - \#2171113 by Pol, wiifm, mw4ll4c3, David_Rothstein,
    douggreen, Fabianx: Settings returned via ajax are not
    run through hook_js_alter()

  - \#3059391 by Liam Morland: Use drupal_http_build_query()
    in drupal_http_request()

  - \#2966335 by mcdruid, dvandijk, David_Rothstein: Avoid
    DrupalRequestSanitizer not found fatal error when
    bootstrap phase order is changed

  - \#3025335 by mcdruid, mfb, joseph.olstad, Fabianx,
    kiamlaluno, Pol: [PHP 7.3] Cannot change session id when
    session is active

  - \#3055805 by mcdruid, greggles, Ayesh, Darren Oh,
    David_Rothstein, sidharrell, pwolanin, mkalkbrenner,
    Sweetchuck, YesCT: file.inc generated .htaccess does not
    cover PHP 7

  - \#3047412 by mcdruid, Chi, beckydev, DKAN, alexpott,
    sammuell, rabbitlair, longwave, greggles, interX: Block
    web.config in .htaccess (and vice-versa)

  - \#3047844 by mfb, jordanwood, Taran2L: Fix test failures
    on PHP 5.3

  - \#3088557: Add mcdruid as provisional Drupal 7 branch
    maintainer

  - \#3051370 by Pol, markcarver, Fabianx: Create 'scripts'
    element to align rendering workflow to how 'styles' are
    handled

  - \#2814031 by Liam Morland: In drupal_http_request(),
    allow passing data as array

  - \#1861604 by hefox, joseph.olstad, Sivaji, mgifford,
    webchick: Skip module_invoke/module_hook in calling
    hook_watchdog (excessive function_exist)

  - \#2666908 by iamEAP, cilefen: HTTP status 200 returned
    for &rdquo;Additional uncaught exception thrown while
    handling exception&rdquo;

  - \#1892654 by Pol, willvincent, Fabianx: D7 Backport:
    theme_table() should take an optional footer variable
    and produce

  - \#3009351 by Pol, mfb, BrianLP: [PHP &ge; 7.2]
    'session_id(): Cannot change session id'

  - \#2684337 by geoffray, Pol, jweowu, Fabianx: Warning:
    uasort() expects parameter 1 to be array, null given in
    node_view_multiple()

  - \#3035772 by Pol: [Regression] Fix default.settings.php
    permission

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php5.laurent-laville.org/compatinfo/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-4917943339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.drupal.org/docs/7/update/introduction)**"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal7 package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/06");
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
if (rpm_check(release:"FC31", reference:"drupal7-7.69-1.fc31")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal7");
}
