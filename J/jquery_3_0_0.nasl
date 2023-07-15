#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125152);
  script_version("1.3");
  script_cvs_date("Date: 2019/10/30 13:24:46");

  script_cve_id("CVE-2015-9251");

  script_name(english:"JQuery < 3.0.0 XSS");
  script_summary(english:"Checks the version of JQuery.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of JQuery library hosted on the remote web
server is prior to 3.0.0. It is, therefore, affected by
a cross site scripting vulnerability when a cross-domain
Ajax request is performed without the dataType option,
causing text/javascript responses to be executed");
  script_set_attribute(attribute:"see_also", value:"https://blog.jquery.com/2016/06/09/jquery-3-0-final-released/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JQuery version 3.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-9251");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jquery_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport", "installed_sw/jquery");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

appname = 'jquery';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80);
app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [{'fixed_version':'3.0.0'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING,flags:{xss:TRUE});
