#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158982);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/09");

  script_cve_id("CVE-2022-24728", "CVE-2022-24729");
  script_xref(name:"IAVA", value:"2022-A-0123-S");

  script_name(english:"Drupal 9.2.x < 9.2.15 / 9.3.x < 9.3.8 Multiple Vulnerabilities (drupal-2022-03-16)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 9.2.x prior to 9.2.15
or 9.3.x prior to 9.3.8. It is, therefore, affected by multiple vulnerabilities.

  - CKEditor4 is an open source what-you-see-is-what-you-get HTML editor. CKEditor4 prior to version 4.18.0
    contains a vulnerability in the `dialog` plugin. The vulnerability allows abuse of a dialog input
    validator regular expression, which can cause a significant performance drop resulting in a browser tab
    freeze. A patch is available in version 4.18.0. There are currently no known workarounds. (CVE-2022-24729)

  - CKEditor4 is an open source what-you-see-is-what-you-get HTML editor. A vulnerability has been discovered
    in the core HTML processing module and may affect all plugins used by CKEditor 4 prior to version 4.18.0.
    The vulnerability allows someone to inject malformed HTML bypassing content sanitization, which could
    result in executing JavaScript code. This problem has been patched in version 4.18.0. There are currently
    no known workarounds. (CVE-2022-24728)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2022-005");
  # https://ckeditor.com/blog/ckeditor-4.18.0-browser-bugfix-and-security-patches/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?526d7751");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ckeditor/ckeditor4");
  # https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-4fc4-4p5g-6w89
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?773fe8cd");
  # https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-f6rf-9m92-x2hh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?742ef187");
  # https://www.drupal.org/docs/contributed-modules/webform/webform-libraries
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63de4ace");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.2.15");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.3.8");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2011-002");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2021-06-29");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/steward");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 9.2.15 / 9.3.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24728");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '9.2', 'fixed_version' : '9.2.15' },
  { 'min_version' : '9.3', 'fixed_version' : '9.3.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
