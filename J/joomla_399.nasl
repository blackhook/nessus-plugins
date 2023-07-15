#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131163);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-14654");

  script_name(english:"Joomla 3.9.x < 3.9.9 Joomla 3.9.9 Release (5772-joomla-3-9-9-release)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 3.9.x prior to
3.9.9. It is, therefore, affected by a vulnerability.

  - In Joomla! 3.9.7 and 3.9.8, inadequate filtering allows
    users authorised to create custom fields to manipulate
    the filtering options and inject an unvalidated option.
    In other words, the filter attribute in subform fields
    allows remote code execution. This is fixed in 3.9.9.
    (CVE-2019-14654)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5772-joomla-3-9-9-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93752a02");
  # https://developer.joomla.org/security-centre/787-20190701-core-filter-attribute-in-subform-fields-allows-remote-code-execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c74ff2e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.9.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14654");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/21");

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
  { 'min_version' : '3.9.7', 'max_version' : '3.9.8', 'fixed_version' : '3.9.9' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
