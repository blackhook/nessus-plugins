#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130970);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-18650", "CVE-2019-18674");

  script_name(english:"Joomla 3.2.x < 3.9.13 Multiple Vulnerabilities (5780-joomla-3-9-13)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 3.2.x prior to
3.9.13. It is, therefore, affected by multiple vulnerabilities.

  - An issue was discovered in Joomla! before 3.9.13. A
    missing token check in com_template causes a CSRF
    vulnerability. (CVE-2019-18650)

  - An issue was discovered in Joomla! before 3.9.13. A
    missing access check in the phputf8 mapping files could
    lead to a path disclosure. (CVE-2019-18674)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5780-joomla-3-9-13.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b67076d1");
  # https://developer.joomla.org/security-centre/794-20191001-core-csrf-in-com-template-overrides-view.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07e076e9");
  # https://developer.joomla.org/security-centre/795-20191002-core-path-disclosure-in-phpuft8-mapping-files.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87e2ad13");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.9.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18650");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/13");

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
  { 'min_version' : '3.2.0', 'max_version' : '3.9.12', 'fixed_version' : '3.9.13' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xsrf':TRUE});
