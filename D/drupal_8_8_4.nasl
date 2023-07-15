#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134702);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_xref(name:"IAVA", value:"2020-A-0118-S");

  script_name(english:"Drupal 8.7.x < 8.7.12 / 8.8.x < 8.8.4 Drupal Vulnerability (SA-CORE-2020-001) (drupal-2020-03-18)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 8.7.x prior to 8.7.12
or 8.8.x prior to 8.8.4. It is, therefore, affected by a vulnerability.

  - The Drupal project uses the third-party library
    CKEditor, which has released a security improvement that
    is needed to protect some Drupal configurations.
    Vulnerabilities are possible if Drupal is configured to
    use the WYSIWYG CKEditor for your sites users. When
    multiple people can edit content, the vulnerability can
    be used to execute XSS attacks against other people,
    including site admins with more access. The latest
    versions of Drupal update CKEditor to 4.14 to mitigate
    the vulnerabilities. (SA-CORE-2020-001)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2020-001");
  # https://ckeditor.com/blog/CKEditor-4.14-with-Paste-from-LibreOffice-released/#security-issues-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54adedaa");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ckeditor/ckeditor4");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.7.12");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.8.4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 8.7.12 / 8.8.4 or later.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '8.7.0', 'fixed_version' : '8.7.12' },
  { 'min_version' : '8.8.0', 'fixed_version' : '8.8.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
