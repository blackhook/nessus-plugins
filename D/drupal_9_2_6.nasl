#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153402);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2020-13673",
    "CVE-2020-13674",
    "CVE-2020-13675",
    "CVE-2020-13676",
    "CVE-2020-13677"
  );
  script_xref(name:"IAVA", value:"2021-A-0412-S");

  script_name(english:"Drupal 8.9.x < 8.9.19 / 9.1.x < 9.1.13 / 9.2.x < 9.2.6 Multiple Vulnerabilities (drupal-2021-09-15)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 8.9.x prior to
8.9.19, 9.1.x prior to 9.1.13, or 9.2.x prior to 9.2.6. It is, therefore, affected by multiple vulnerabilities.

  - Under some circumstances, the Drupal core JSON:API module does not properly restrict access to certain
    content, which may result in unintended access bypass. Sites that do not have the JSON:API module enabled
    are not affected. This advisory is not covered by Drupal Steward. (CVE-2020-13677)

  - The QuickEdit module does not properly check access to fields in some circumstances, which can lead to
    unintended disclosure of field data. Sites are only affected if the QuickEdit module (which comes with the
    Standard profile) is installed. This advisory is not covered by Drupal Steward. (CVE-2020-13676)

  - Drupal's JSON:API and REST/File modules allow file uploads through their HTTP APIs. The modules do not
    correctly run all file validation, which causes an access bypass vulnerability. An attacker might be able
    to upload files that bypass the file validation process implemented by modules on the site. This
    vulnerability is mitigated by three factors: The JSON:API or REST File upload modules must be enabled on
    the site. An attacker must have access to a file upload via JSON:API or REST. The site must employ a file
    validation module. This advisory is not covered by Drupal Steward. Also see GraphQL - Moderately critical
    - Access bypass - SA-CONTRIB-2021-029 which addresses a similar vulnerability for that module.
    (CVE-2020-13675)

  - The QuickEdit module does not properly validate access to routes, which could allow cross-site request
    forgery under some circumstances and lead to possible data integrity issues. Sites are only affected if
    the QuickEdit module (which comes with the Standard profile) is installed. Removing the access in-place
    editing permission from untrusted users will not fully mitigate the vulnerability. This advisory is not
    covered by Drupal Steward. (CVE-2020-13674)

  - The Drupal core Media module provides a filter to allow embedding internal and external media in content
    fields. In certain circumstances, the filter could allow an unprivileged user to inject HTML into a page
    when it is accessed by a trusted user with permission to embed media. In some cases, this could lead to
    cross-site scripting. This advisory is not covered by Drupal Steward. Also see Entity Embed - Moderately
    critical - Cross Site Request Forgery - SA-CONTRIB-2021-028 which addresses a similar vulnerability for
    that module. (CVE-2020-13673)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2021-010");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.9.19");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.1.13");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.2.6");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/steward");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2021-009");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/3227039");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2021-008");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-contrib-2021-029");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2021-007");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2021-006");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-contrib-2021-028");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 8.9.19 / 9.1.13 / 9.2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13675");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var port = get_http_port(default:80, php:TRUE);

var app_info = vcf::get_app_info(app:'Drupal', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '8.9', 'fixed_version' : '8.9.19' },
  { 'min_version' : '9.1', 'fixed_version' : '9.1.13' },
  { 'min_version' : '9.2', 'fixed_version' : '9.2.6' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
