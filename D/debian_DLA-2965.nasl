#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2965. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159321);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/29");

  script_cve_id(
    "CVE-2018-10060",
    "CVE-2018-10061",
    "CVE-2019-11025",
    "CVE-2020-7106",
    "CVE-2020-13230",
    "CVE-2020-23226",
    "CVE-2021-23225",
    "CVE-2022-0730"
  );

  script_name(english:"Debian DLA-2965-1 : cacti - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-2965 advisory.

  - Cacti before 1.1.37 has XSS because it does not properly reject unintended characters, related to use of
    the sanitize_uri function in lib/functions.php. (CVE-2018-10060)

  - Cacti before 1.1.37 has XSS because it makes certain htmlspecialchars calls without the ENT_QUOTES flag
    (these calls occur when the html_escape function in lib/html.php is not used). (CVE-2018-10061)

  - In clearFilter() in utilities.php in Cacti before 1.2.3, no escaping occurs before printing out the value
    of the SNMP community string (SNMP Options) in the View poller cache, leading to XSS. (CVE-2019-11025)

  - In Cacti before 1.2.11, disabling a user account does not immediately invalidate any permissions granted
    to that account (e.g., permission to view logs). (CVE-2020-13230)

  - Multiple Cross Site Scripting (XSS) vulneratiblities exist in Cacti 1.2.12 in (1) reports_admin.php, (2)
    data_queries.php, (3) data_input.php, (4) graph_templates.php, (5) graphs.php, (6) reports_admin.php, and
    (7) data_input.php. (CVE-2020-23226)

  - Cacti 1.2.8 has stored XSS in data_sources.php, color_templates_item.php, graphs.php, graph_items.php,
    lib/api_automation.php, user_admin.php, and user_group_admin.php, as demonstrated by the description
    parameter in data_sources.php (a raw string from the database that is displayed by $header to trigger the
    XSS). (CVE-2020-7106)

  - Cacti 1.1.38 allows authenticated users with User Management permissions to inject arbitrary web script or
    HTML in the new_username field during creation of a new user via Copy method at user_admin.php.
    (CVE-2021-23225)

  - Under certain ldap conditions, Cacti authentication can be bypassed with certain credential types.
    (CVE-2022-0730)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=926700");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/cacti");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2965");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10060");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10061");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-11025");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-13230");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-23226");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-7106");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23225");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0730");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/cacti");
  script_set_attribute(attribute:"solution", value:
"Upgrade the cacti packages.

For Debian 9 stretch, these problems have been fixed in version 0.8.8h+ds1-10+deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0730");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'cacti', 'reference': '0.8.8h+ds1-10+deb9u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cacti');
}
