#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-edf90410ea.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117965);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-0503", "CVE-2018-0504", "CVE-2018-0505");
  script_xref(name:"FEDORA", value:"2018-edf90410ea");

  script_name(english:"Fedora 27 : mediawiki (2018-edf90410ea)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"https://www.mediawiki.org/wiki/Release_notes/1.29#MediaWiki_1.29.3

  - (T169545, CVE-2018-0503) SECURITY: $wgRateLimits entry
    for 'user' overrides 'newbie'.

  - (T194605, CVE-2018-0505) SECURITY: BotPasswords can
    bypass CentralAuth's account lock.

  - (T180551) Fix LanguageSrTest for language converter

  - (T180552) Fix langauge converter parser test with
    self-close tags

  - (T180537) Remove $wgAuth usage from wrapOldPasswords.php

  - (T180485) InputBox: Have inputbox langconvert certain
    attributes

  - (T161732, T181547) Upgraded Moment.js from v2.15.0 to
    v2.19.3.

  - (T172927) Drop vendor from MW release branch

  - (T87572) Make FormatMetadata::flattenArrayReal() work
    for an associative array

  - Updated composer/spdx-licenses from 1.1.4 to 1.3.0
    (development dependency).

  - (T189567) the CLI installer (maintenance/install.php)
    learned to detect and include extensions. Pass
    --with-extensions to enable that feature.

  - (T182381) Mask deprecated call in WatchedItemUnitTest

  - (T190503) Let built-in web server (maintenance/dev)
    handle .php requests.

  - The karma qunit tests would fail on some configuration
    due to headers already sent. Check headers_sent() before
    sending cpPosTime headers

  - (T167507) selenium: Run Chrome headlessly.

  - selenium: Pass -no-sandbox to Chrome under Docker

  - (T191247) Use MediaWiki\SuppressWarnings around
    trigger_error() instead @

  - (T75174, T161041) Unit test
    ChangesListSpecialPageTest::testFilterUserExpLevel fails
    under SQLite.

  - (T192584) Stop incorrectly passing USE INDEX to
    RecentChange::newFromConds().

  - (T179190) selenium: Move test running logic from
    package.json to selenium.sh.

  - (T117839, T193200) PDFHandler: Fix for pdfinfo changes
    in poppler-utils 0.48.

  - Add default edit rate limit of 90 edits/minute for all
    users.

  - (T196125) php-memcached 3.0 (provided with PHP 7.0) is
    now supported.

  - (T196672) The mtime of extension.json files is now able
    to be zero

  - (T180403) Validate $length in padleft/padright parser
    functions.

  - (T143790) Make $wgEmailConfirmToEdit only affect edit
    actions.

  - (T194237) Special:BotPasswords now requires
    reauthentication.

  - (T191608, T187638) Add 'logid' parameter to Special:Log.

  - (T176097) resourceloader: Disable a flaky
    MessageBlobStoreTest case

  - (T193829) Indicate when a Bot Password needs reset.

  - (T151415) Log email changes.

  - (T118420) Unbreak Oracle installer.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-edf90410ea"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mediawiki package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mediawiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^27([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 27", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC27", reference:"mediawiki-1.29.3-1.fc27")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mediawiki");
}
