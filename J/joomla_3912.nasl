#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129303);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-16725");

  script_name(english:"Joomla 3.0.x < 3.9.12 Joomla 3.9.12 Release (5776-joomla-3-9-12)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 3.0.x prior to
3.9.12. It is, therefore, affected by a vulnerability.

  - Inadequate escaping allowed XSS attacks using the logo
    parameter of the default templates. (CVE-2019-16725)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5776-joomla-3-9-12.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9e86f76");
  # https://developer.joomla.org/security-centre/791-20190901-core-xss-in-logo-parameter-of-default-templates.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?413fb599");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.9.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16725");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);
port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'Joomla!', port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '3.0.0', 'max_version' : '3.9.11', 'fixed_version' : '3.9.12' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
