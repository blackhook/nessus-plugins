#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(40362);
  script_version("1.104");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/04");

  script_xref(name:"IAVA", value:"0001-A-0565");

  script_name(english:"Mozilla Foundation Unsupported Application Detection");
  script_summary(english:"Checks if any Mozilla application versions are unsupported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains one or more unsupported applications from the
Mozilla Foundation.");
  script_set_attribute(attribute:"description", value:
"According to its version, there is at least one unsupported Mozilla
application (Firefox, Thunderbird, and/or SeaMonkey) installed on the
remote host. This version of the software is no longer actively
maintained.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/firefox/organizations/faq/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/known-vulnerabilities/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/firefox/new/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/thunderbird/");
  script_set_attribute(attribute:"see_also", value:"https://www.seamonkey-project.org/releases/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_ports("installed_sw/Mozilla Firefox", "installed_sw/Mozilla Firefox ESR", "installed_sw/Mozilla Thunderbird", "installed_sw/Mozilla Thunderbird ESR", "installed_sw/SeaMonkey");

  exit(0);
}

include('install_func.inc');
include('debug.inc');

var now = get_kb_item("/tmp/start_time");
if (empty_or_null(now))
  now = int(gettimeofday());

var all_latest_version_data = make_array(
  'Mozilla Firefox'        , "100.0.2",
  'Mozilla Firefox ESR'    , "91.9.1",
  'Mozilla Thunderbird'    , "91.9.1",
  'Mozilla Thunderbird ESR', "Defunct.",
  'SeaMonkey'              , "2.53.12"
);

var all_unsupported_data = make_array(

  ##########
  # Mozilla Firefox (NOT ESR)
  ##########
  'Mozilla Firefox', make_array(
    '^[1][0][0]\\.[0]\\.[0-1]', 'https://www.mozilla.org/en-US/firefox/releases/',
    '^[5-9][0-9]\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/#firefox99',
    '^4[0-9]\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/#firefox49',
    '^3[0-9]\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/#firefox39',
    '^2[0-9]\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/#firefox29',
    '^1[0-9]\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/#firefox19',
    '^[4-9]\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/#firefox9',
    '^3\\.6\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox-3.6/',
    '^3\\.5\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox-3.5/',
    '^3\\.0\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox-3.0/',
    '^2\\.0\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox-2.0/',
    '^1\\.5\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox-1.5/',
    '^1\\.0\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox-1.0/',
    '^0\\.', NULL
  ),

  ##########
  # Mozilla Firefox ESR
  ########## Firefox
  'Mozilla Firefox ESR', make_array(
    '^[9][1]\\.[0-9]\\.0', 'https://www.mozilla.org/en-US/firefox/91.9/releasenotes/',
    '^[6-8][0-9]\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox-esr/#firefoxesr78.15',
    '^5[01]\\.|^52\\.[0-8]\\.', 'https://www.mozilla.org/en-US/firefox/releases/',
    '^[1-4][0-9]\\.', 'https://www.mozilla.org/en-US/firefox/releases/',
    '^0\\.', NULL
  ),

  ##########
  # Mozilla Thunderbird (NOT ESR)
  ##########
  'Mozilla Thunderbird', make_array(
    '^[9][0-1]\\.[0-9]\\.0', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/thunderbird/#thunderbird91.9',
    '^[6-8][0-9]\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/thunderbird/#thunderbird78.14',
    '^52\\.[0-9]\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/thunderbird/#thunderbird52.9',
    '^[1-4][0-9]\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/thunderbird/#thunderbird45.8',
    '^[4-9]\\.', 'https://www.mozilla.org/en-US/thunderbird/releases/',
    '^3\\.1\\.', 'http://www.mozilla.org/security/known-vulnerabilities/thunderbird3.1.html',
    '^3\\.0\\.', 'http://www.mozilla.org/security/known-vulnerabilities/thunderbird30.html',
    '^2\\.0\\.', 'http://www.mozilla.org/security/known-vulnerabilities/thunderbird20.html',
    '^1\\.5\\.', 'http://www.mozilla.org/security/known-vulnerabilities/thunderbird15.html',
    '^1\\.0\\.', 'http://www.mozilla.org/security/known-vulnerabilities/thunderbird10.html',
    '^0\\.', NULL
  ),

  ##########
  # Mozilla Thunderbird ESR
  # Defunct - *all* versions of ESR are no longer supported.
  ##########
  'Mozilla Thunderbird ESR', make_array(
    '^\\d', 'https://www.thunderbird.net/en-US/thunderbird/releases/',
    '^0\\.', NULL
  ),

  ##########
  # SeaMmonkey
  ##########
  'SeaMonkey', make_array(
    '^2\\.[5][3]\\.[0-1][0-1]', 'https://www.seamonkey-project.org/releases/',
    '^2\\.[5][3]\\.[0-9]$', 'https://www.seamonkey-project.org/releases/',
    '^2\\.[0-5][0-2]\\.', 'https://www.seamonkey-project.org/releases/',
    '^2\\.[0-9]\\.', 'https://www.seamonkey-project.org/releases/',
    '^1\\.[0-9]\\.', 'https://www.seamonkey-project.org/releases/',
    '^0\\.', NULL
  )
);

var products = make_list(
  "Mozilla Firefox",
  "Mozilla Firefox ESR",
  "Mozilla Thunderbird",
  "Mozilla Thunderbird ESR",
  "SeaMonkey"
);

# Branch on product
var product = branch(products);

# Branch on install
var install = get_single_install(app_name:product);
var version = install['version'];
var path    = install['path'];
var eol_url, match, regex, keys, version_highlevel, cpe_base , port, report;

## Future dates to be considered
## https://en.wikipedia.org/wiki/Firefox_version_history

if (now > 1653955200) # Tuesday, 31 May 2022, 12:00:00 AM GMT
{
  all_latest_version_data['Mozilla Firefox'] = "101.0.0";
  all_unsupported_data['Mozilla Firefox']['^100\\.'] = 'https://www.mozilla.org/en-US/firefox/100.0.2/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "91.10.0";
  all_unsupported_data['Mozilla Firefox ESR']['^(90\\.|91\\.[0-9]([^0-9|$]))'] = 'https://www.mozilla.org/en-US/firefox/91.9.1/releasenotes/';
}
if (now > 1656374400) # Tuesday, 28 June 2022, 12:00:00 AM GMT
{
  all_latest_version_data['Mozilla Firefox'] = "102.0.0";
  all_unsupported_data['Mozilla Firefox']['^101\\.'] = 'https://www.mozilla.org/en-US/firefox/101.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "91.11.0 / 102.0.0";
  all_unsupported_data['Mozilla Firefox ESR']['^91\\.[0-1][0]([^0-9|$])'] = 'https://www.mozilla.org/en-US/firefox/91.10.0/releasenotes/';
  all_unsupported_data['Mozilla Firefox ESR']['^101\\.'] = 'https://www.mozilla.org/en-US/firefox/101.0/releasenotes/';
}
if (now > 1658793600) # Tuesday, 26 July 2022, 12:00:00 AM GMT
{
  all_latest_version_data['Mozilla Firefox'] = "103.0.0";
  all_unsupported_data['Mozilla Firefox']['^102\\.'] = 'https://www.mozilla.org/en-US/firefox/102.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "91.12.0 / 102.1.0";
  all_unsupported_data['Mozilla Firefox ESR']['^[9][1]\\.[1][0-1]'] = 'https://www.mozilla.org/en-US/firefox/91.11.0/releasenotes/';
  all_unsupported_data['Mozilla Firefox ESR']['^102\\.0([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/102.0/releasenotes/';
}
if (now > 1661212800) # Tuesday, 23 August 2022, 12:00:00 AM GMT
{
  all_latest_version_data['Mozilla Firefox'] = "104.0.0";
  all_unsupported_data['Mozilla Firefox']['^103\\.'] = 'https://www.mozilla.org/en-US/firefox/103.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "91.13.0 / 102.2.0";
  all_unsupported_data['Mozilla Firefox ESR']['^[9][1]\\.[1][0-2]'] = 'https://www.mozilla.org/en-US/firefox/91.12.0/releasenotes/';
  all_unsupported_data['Mozilla Firefox ESR']['^102\\.1([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/102.1.0/releasenotes/';
}
if (now > 1663632000) # Tuesday, 20 September 2022, 12:00:00 AM GMT
{
  all_latest_version_data['Mozilla Firefox'] = "105.0.0";
  all_unsupported_data['Mozilla Firefox']['^104\\.'] = 'https://www.mozilla.org/en-US/firefox/104.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "102.3.0";
  all_unsupported_data['Mozilla Firefox ESR']['^[9][0-9]\\.[0-9][0-9]'] = 'https://www.mozilla.org/en-US/firefox/91.13.0/releasenotes/';
  all_unsupported_data['Mozilla Firefox ESR']['^102\\.2([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/102.2.0/releasenotes/';
}
if (now > 1666051200) # GMT: Tuesday, 18 October 2022, 12:00:00 AM GMT
{
  all_latest_version_data['Mozilla Firefox'] = "106.0.0";
  all_unsupported_data['Mozilla Firefox']['^105\\.'] = 'https://www.mozilla.org/en-US/firefox/105.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "102.4.0";
  all_unsupported_data['Mozilla Firefox ESR']['^102\\.3([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/102.3.0/releasenotes/';
}
if (now > 1668470400) # GMT: Tuesday, 15 November 2022, 12:00:00 AM GMT
{
  all_latest_version_data['Mozilla Firefox'] = "107.0.0";
  all_unsupported_data['Mozilla Firefox']['^106\\.'] = 'https://www.mozilla.org/en-US/firefox/106.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "102.5.0";
  all_unsupported_data['Mozilla Firefox ESR']['^102\\.4([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/102.4.0/releasenotes/';
}
if (now > 1670889600) # GMT: Tuesday, December 13, 2022 12:00:00 AM
{
  all_latest_version_data['Mozilla Firefox'] = "108.0.0";
  all_unsupported_data['Mozilla Firefox']['^107\\.'] = 'https://www.mozilla.org/en-US/firefox/107.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "102.6.0";
  all_unsupported_data['Mozilla Firefox ESR']['^102\\.5([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/102.5.0/releasenotes/';
}
if (now > 1673913600) # GMT: Tuesday, January 17, 2023 12:00:00 AM
{
  all_latest_version_data['Mozilla Firefox'] = "109.0.0";
  all_unsupported_data['Mozilla Firefox']['^108\\.'] = 'https://www.mozilla.org/en-US/firefox/108.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "102.7.0";
  all_unsupported_data['Mozilla Firefox ESR']['^102\\.6([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/102.6.0/releasenotes/';
}
if (now > 1676332800) # GMT: Tuesday, February 14, 2023 12:00:00 AM
{
  all_latest_version_data['Mozilla Firefox'] = "110.0.0";
  all_unsupported_data['Mozilla Firefox']['^109\\.'] = 'https://www.mozilla.org/en-US/firefox/109.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "102.8.0";
  all_unsupported_data['Mozilla Firefox ESR']['^102\\.7([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/102.7.0/releasenotes/';
}
if (now > 1678752000) # GMT: Tuesday, March 14, 2023 12:00:00 AM
{
  all_latest_version_data['Mozilla Firefox'] = "111.0.0";
  all_unsupported_data['Mozilla Firefox']['^110\\.'] = 'https://www.mozilla.org/en-US/firefox/110.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "102.9.0";
  all_unsupported_data['Mozilla Firefox ESR']['^102\\.8([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/102.8.0/releasenotes/';
}
if (now > 1681171200) # GMT: Tuesday, April 11, 2023 12:00:00 AM
{
  all_latest_version_data['Mozilla Firefox'] = "112.0.0";
  all_unsupported_data['Mozilla Firefox']['^111\\.'] = 'https://www.mozilla.org/en-US/firefox/111.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "102.10.0";
  all_unsupported_data['Mozilla Firefox ESR']['^102\\.9([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/102.9.0/releasenotes/';
}
if (now > 1683590400) # GMT: Tuesday, May 9, 2023 12:00:00 AM
{
  all_latest_version_data['Mozilla Firefox'] = "113.0.0";
  all_unsupported_data['Mozilla Firefox']['^112\\.'] = 'https://www.mozilla.org/en-US/firefox/112.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "102.11.0";
  all_unsupported_data['Mozilla Firefox ESR']['^102\\.10([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/102.10.0/releasenotes/';
}
if (now > 1686009600) # GMT: Tuesday, June 6, 2023 12:00:00 AM
{
  all_latest_version_data['Mozilla Firefox'] = "114.0.0";
  all_unsupported_data['Mozilla Firefox']['^113\\.'] = 'https://www.mozilla.org/en-US/firefox/113.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "102.12.0";
  all_unsupported_data['Mozilla Firefox ESR']['^102\\.11([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/102.11.0/releasenotes/';
}
if (now > 1688428800) # GMT: Tuesday, July 4, 2023 12:00:00 AM
{
  all_latest_version_data['Mozilla Firefox'] = "115.0.0";
  all_unsupported_data['Mozilla Firefox']['^114\\.'] = 'https://www.mozilla.org/en-US/firefox/114.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "102.13.0 / 115.0.0";
  all_unsupported_data['Mozilla Firefox ESR']['^102\\.12([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/102.12.0/releasenotes/';
}
if (now > 1690848000) # GMT: Tuesday, August 1, 2023 12:00:00 AM
{
  all_latest_version_data['Mozilla Firefox'] = "116.0.0";
  all_unsupported_data['Mozilla Firefox']['^115\\.'] = 'https://www.mozilla.org/en-US/firefox/115.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "102.14.0 / 115.1.0";
  all_unsupported_data['Mozilla Firefox ESR']['^102\\.13([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/102.13.0/releasenotes/';
  all_unsupported_data['Mozilla Firefox ESR']['^115\\.0([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/115.0.0/releasenotes/';
}
if (now > 1693267200) # GMT: Tuesday, August 29, 2023 12:00:00 AM
{
  all_latest_version_data['Mozilla Firefox'] = "117.0.0";
  all_unsupported_data['Mozilla Firefox']['^116\\.'] = 'https://www.mozilla.org/en-US/firefox/116.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "102.15.0 / 115.2.0";
  all_unsupported_data['Mozilla Firefox ESR']['^102\\.14([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/102.14.0/releasenotes/';
  all_unsupported_data['Mozilla Firefox ESR']['^115\\.1([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/115.1.0/releasenotes/';
}
if (now > 1695686400) # GMT: Tuesday, September 26, 2023 12:00:00 AM
{
  all_latest_version_data['Mozilla Firefox'] = "118.0.0";
  all_unsupported_data['Mozilla Firefox']['^117\\.'] = 'https://www.mozilla.org/en-US/firefox/117.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "115.3.0";
  all_unsupported_data['Mozilla Firefox ESR']['^102\\.'] = 'https://www.mozilla.org/en-US/firefox/102.14.0/releasenotes/';
  all_unsupported_data['Mozilla Firefox ESR']['^115\\.2([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/115.2.0/releasenotes/';
}
if (now > 1698105600) # GMT: Tuesday, October 24, 2023 12:00:00 AM
{
  all_latest_version_data['Mozilla Firefox'] = "119.0.0";
  all_unsupported_data['Mozilla Firefox']['^118\\.'] = 'https://www.mozilla.org/en-US/firefox/118.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "115.4.0";
  all_unsupported_data['Mozilla Firefox ESR']['^115\\.3([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/115.3.0/releasenotes/';
}
if (now > 1700524800) # GMT: Tuesday, November 21, 2023 12:00:00 AM
{
  all_latest_version_data['Mozilla Firefox'] = "120.0.0";
  all_unsupported_data['Mozilla Firefox']['^119\\.'] = 'https://www.mozilla.org/en-US/firefox/119.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "115.5.0";
  all_unsupported_data['Mozilla Firefox ESR']['^115\\.4([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/115.4.0/releasenotes/';
}
if (now > 1702944000) # GMT: Tuesday, December 19, 2023 12:00:00 AM
{
  all_latest_version_data['Mozilla Firefox'] = "121.0.0";
  all_unsupported_data['Mozilla Firefox']['^120\\.'] = 'https://www.mozilla.org/en-US/firefox/120.0/releasenotes/';
  all_latest_version_data['Mozilla Firefox ESR'] = "115.6.0";
  all_unsupported_data['Mozilla Firefox ESR']['^115\\.5([^0-9]|$)'] = 'https://www.mozilla.org/en-US/firefox/115.5.0/releasenotes/';
}

var unsupported_data = all_unsupported_data[product];
var latest_version = all_latest_version_data[product];

# Check version for unsupported status
foreach regex (sort(keys(unsupported_data)))
{
  if (!preg(pattern:regex, string:version)) continue;

  eol_url = unsupported_data[regex];

  match = pregmatch(pattern:"^([0-9]+)\.", string:version);
  if (isnull(match)) version_highlevel = version;
  else version_highlevel = match[1];

  cpe_base = tolower(str_replace(string:product, find:"Mozilla ", replace:""));
  cpe_base = str_replace(string:cpe_base, find:" ", replace:"_");

  register_unsupported_product(
    product_name : product,
    cpe_base     : "mozilla:" + cpe_base,
    version      : version_highlevel
  );
  break;
}

if (eol_url)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + product +
      '\n  Path              : ' + path    +
      '\n  Installed version : ' + version +
      '\n  Latest version    : ' + latest_version +
      '\n  EOL URL           : ' + eol_url +
      '\n';
    security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  }
  else security_report_v4(port:port, severity:SECURITY_HOLE);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, product, version, path);
