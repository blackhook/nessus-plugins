#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156863);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2010-5312",
    "CVE-2016-7103",
    "CVE-2021-41182",
    "CVE-2021-41183",
    "CVE-2021-41184"
  );
  script_xref(name:"IAVA", value:"2016-A-0285-S");
  script_xref(name:"IAVA", value:"2018-A-0230-S");
  script_xref(name:"IAVB", value:"2021-B-0071-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Drupal 7.x < 7.86 / 9.2.x < 9.2.11 / 9.3.x < 9.3.3 Multiple Vulnerabilities (drupal-2022-01-19)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 7.x prior to 7.86,
9.2.x prior to 9.2.11, or 9.3.x prior to 9.3.3. It is, therefore, affected by multiple vulnerabilities.

  - Cross-site scripting (XSS) vulnerability in jquery.ui.dialog.js in the Dialog widget in jQuery UI before
    1.10.0 allows remote attackers to inject arbitrary web script or HTML via the title option.
    (CVE-2010-5312)

  - Cross-site scripting (XSS) vulnerability in jQuery UI before 1.12.0 might allow remote attackers to inject
    arbitrary web script or HTML via the closeText parameter of the dialog function. (CVE-2016-7103)

  - jQuery-UI is the official jQuery user interface library. Prior to version 1.13.0, accepting the value of
    the `altField` option of the Datepicker widget from untrusted sources may execute untrusted code. The
    issue is fixed in jQuery UI 1.13.0. Any string value passed to the `altField` option is now treated as a
    CSS selector. A workaround is to not accept the value of the `altField` option from untrusted sources.
    (CVE-2021-41182)

  - jQuery-UI is the official jQuery user interface library. Prior to version 1.13.0, accepting the value of
    various `*Text` options of the Datepicker widget from untrusted sources may execute untrusted code. The
    issue is fixed in jQuery UI 1.13.0. The values passed to various `*Text` options are now always treated as
    pure text, not HTML. A workaround is to not accept the value of the `*Text` options from untrusted
    sources. (CVE-2021-41183)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2022-002");
  script_set_attribute(attribute:"see_also", value:"https://blog.jqueryui.com/2021/10/jquery-ui-1-13-0-released/");
  # https://github.com/jquery/jquery-ui/security/advisories/GHSA-9gj3-hwp5-pmwc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92b10be6");
  # https://github.com/jquery/jquery-ui/security/advisories/GHSA-j7qv-pgf6-hvh4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85264131");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.86");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/jquery_update");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.2.11");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.3.3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.86 / 9.2.11 / 9.3.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41184");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '7.0', 'fixed_version' : '7.86' },
  { 'min_version' : '9.2', 'fixed_version' : '9.2.11' },
  { 'min_version' : '9.3', 'fixed_version' : '9.3.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
