#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165520);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/27");

  script_cve_id("CVE-2022-39261");
  script_xref(name:"IAVA", value:"2022-A-0449-S");

  script_name(english:"Drupal 9.3.x < 9.3.22 / 9.4.x < 9.4.7 Drupal Vulnerability (SA-CORE-2022-016) ");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 9.3.x prior to 9.3.22
or 9.4.x prior to 9.4.7. It is, therefore, affected by a vulnerability.

  - Twig is a template language for PHP. Versions 1.x prior to 1.44.7, 2.x prior to 2.15.3, and 3.x prior to
    3.4.3 encounter an issue when the filesystem loader loads templates for which the name is a user input. It
    is possible to use the `source` or `include` statement to read arbitrary files from outside the templates'
    directory when using a namespace like `@somewhere/../some.file`. In such a case, validation is bypassed.
    Versions 1.44.7, 2.15.3, and 3.4.3 contain a fix for validation of such template names. There are no known
    workarounds aside from upgrading. (CVE-2022-39261)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2022-016");
  # https://symfony.com/blog/twig-security-release-possibility-to-load-a-template-outside-a-configured-directory-when-using-the-filesystem-loader
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f6ab4df");
  script_set_attribute(attribute:"see_also", value:"https://twig.symfony.com/");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.3.22");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.4.7");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2021-06-29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 9.3.22 / 9.4.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39261");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '9.3', 'fixed_version' : '9.3.22' },
  { 'min_version' : '9.4', 'fixed_version' : '9.4.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
