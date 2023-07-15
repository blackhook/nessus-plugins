#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136745);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-11022", "CVE-2020-11023");
  script_xref(name:"IAVB", value:"2020-B-0030");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Drupal 7.0.x < 7.70 / 7.0.x < 7.70 / 8.7.x < 8.7.14 / 8.8.x < 8.8.6 Multiple Vulnerabilities (drupal-2020-05-20)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 7.0.x prior to 7.70,
7.0.x prior to 7.70, 8.7.x prior to 8.7.14, or 8.8.x prior to 8.8.6. It is, therefore, affected by multiple
vulnerabilities.

  - In jQuery versions greater than or equal to 1.2 and
    before 3.5.0, passing HTML from untrusted sources - even
    after sanitizing it - to one of jQuery's DOM
    manipulation methods (i.e. .html(), .append(), and
    others) may execute untrusted code. This problem is
    patched in jQuery 3.5.0. (CVE-2020-11022)

  - In jQuery versions greater than or equal to 1.0.3 and
    before 3.5.0, passing HTML containing  elements
    from untrusted sources - even after sanitizing it - to
    one of jQuery's DOM manipulation methods (i.e. .html(),
    .append(), and others) may execute untrusted code. This
    problem is patched in jQuery 3.5.0. (CVE-2020-11023)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2020-003");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.70");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2020-002");
  # https://blog.jquery.com/2020/05/04/jquery-3-5-1-released-fixing-a-regression/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f249edf4");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Software_regression");
  # https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07eeffa7");
  # https://github.com/jquery/jquery/security/advisories/GHSA-jpcq-cgw6-v4j6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc025732");
  script_set_attribute(attribute:"see_also", value:"https://html.spec.whatwg.org/multipage/custom-elements.html");
  script_set_attribute(attribute:"see_also", value:"https://jquery.com/upgrade-guide/3.5/#description-of-the-change");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.7.14");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.8.6");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/issues/drupal");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/jquery_update");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/security-team/report-issue");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.70 / 7.70 / 8.7.14 / 8.8.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'Drupal', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.70' },
  { 'min_version' : '8.7', 'fixed_version' : '8.7.14' },
  { 'min_version' : '8.8', 'fixed_version' : '8.8.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
