#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3117. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(165431);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/25");

  script_cve_id(
    "CVE-2021-44856",
    "CVE-2022-28201",
    "CVE-2022-28202",
    "CVE-2022-28203",
    "CVE-2022-34911",
    "CVE-2022-34912"
  );

  script_name(english:"Debian DLA-3117-1 : mediawiki - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3117 advisory.

  - An issue was discovered in MediaWiki before 1.35.6, 1.36.x before 1.36.4, and 1.37.x before 1.37.2. Users
    with the editinterface permission can trigger infinite recursion, because a bare local interwiki is
    mishandled for the mainpage message. (CVE-2022-28201)

  - An XSS issue was discovered in MediaWiki before 1.35.6, 1.36.x before 1.36.4, and 1.37.x before 1.37.2.
    The widthheight, widthheightpage, and nbytes properties of messages are not escaped when used in galleries
    or Special:RevisionDelete. (CVE-2022-28202)

  - A denial-of-service issue was discovered in MediaWiki before 1.35.6, 1.36.x before 1.36.4, and 1.37.x
    before 1.37.2. When many files exist, requesting Special:NewFiles with actor as a condition can result in
    a very long running query. (CVE-2022-28203)

  - An issue was discovered in MediaWiki before 1.35.7, 1.36.x and 1.37.x before 1.37.3, and 1.38.x before
    1.38.1. XSS can occur in configurations that allow a JavaScript payload in a username. After account
    creation, when it sets the page title to Welcome followed by the username, the username is not escaped:
    SpecialCreateAccount::successfulAction() calls ::showSuccessPage() with a message as second parameter, and
    OutputPage::setPageTitle() uses text(). (CVE-2022-34911)

  - An issue was discovered in MediaWiki before 1.37.3 and 1.38.x before 1.38.1. The contributions-title, used
    on Special:Contributions, is used as page title without escaping. Hence, in a non-default configuration
    where a username contains HTML entities, it won't be escaped. (CVE-2022-34912)

  - Mediawiki reports: (T292763. CVE-2021-44854) REST API incorrectly publicly caches             autocomplete
    search results from private wikis. (T271037, CVE-2021-44856) Title blocked in AbuseFilter can be created
    via             Special:ChangeContentModel. (T297322, CVE-2021-44857) Unauthorized users can use
    action=mcrundo to             replace the content of arbitrary pages.  (T297322, CVE-2021-44858)
    Unauthorized users can view contents of private             wikis using various actions. (T297574,
    CVE-2021-45038) Unauthorized users can access private wiki             contents using rollback action
    (T293589, CVE-2021-44855) Blind Stored XSS in VisualEditor media dialog. (T294686) Special:Nuke doesn't
    actually delete pages. (CVE-2021-44856)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/mediawiki");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3117");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44856");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28201");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28202");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28203");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-34911");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-34912");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/mediawiki");
  script_set_attribute(attribute:"solution", value:
"Upgrade the mediawiki packages.

For Debian 10 buster, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34912");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mediawiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mediawiki-classes");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'mediawiki', 'reference': '1:1.31.16-1+deb10u3'},
    {'release': '10.0', 'prefix': 'mediawiki-classes', 'reference': '1:1.31.16-1+deb10u3'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mediawiki / mediawiki-classes');
}
