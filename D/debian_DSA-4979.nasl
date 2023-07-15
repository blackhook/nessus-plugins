#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4979. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153862);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id(
    "CVE-2021-35197",
    "CVE-2021-41798",
    "CVE-2021-41799",
    "CVE-2021-41800",
    "CVE-2021-41801"
  );

  script_name(english:"Debian DSA-4979-1 : mediawiki - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-4979 advisory.

  - In MediaWiki before 1.31.15, 1.32.x through 1.35.x before 1.35.3, and 1.36.x before 1.36.1, bots have
    certain unintended API access. When a bot account has a sitewide block applied, it is able to still
    purge pages through the MediaWiki Action API (which a sitewide block should have prevented).
    (CVE-2021-35197)

  - MediaWiki before 1.36.2 allows XSS. Month related MediaWiki messages are not escaped before being used on
    the Special:Search results page. (CVE-2021-41798)

  - MediaWiki before 1.36.2 allows a denial of service (resource consumption because of lengthy query
    processing time). ApiQueryBacklinks (action=query&list;=backlinks) can cause a full table scan.
    (CVE-2021-41799)

  - MediaWiki before 1.36.2 allows a denial of service (resource consumption because of lengthy query
    processing time). Visiting Special:Contributions can sometimes result in a long running SQL query because
    PoolCounter protection is mishandled. (CVE-2021-41800)

  - The ReplaceText extension through 1.41 for MediaWiki has Incorrect Access Control. When a user is blocked
    after submitting a replace job, the job is still run, even if it may be run at a later time (due to the
    job queue backlog) (CVE-2021-41801)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/mediawiki");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4979");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-35197");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41798");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41799");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41800");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41801");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/mediawiki");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/mediawiki");
  script_set_attribute(attribute:"solution", value:
"Upgrade the mediawiki packages.

For the stable distribution (bullseye), these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41801");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mediawiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mediawiki-classes");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'mediawiki', 'reference': '1:1.31.16-1~deb10u1'},
    {'release': '10.0', 'prefix': 'mediawiki-classes', 'reference': '1:1.31.16-1~deb10u1'},
    {'release': '11.0', 'prefix': 'mediawiki', 'reference': '1:1.35.4-1~deb11u1'},
    {'release': '11.0', 'prefix': 'mediawiki-classes', 'reference': '1:1.35.4-1~deb11u1'}
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
