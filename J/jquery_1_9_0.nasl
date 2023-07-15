#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135011);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/26");

  script_cve_id("CVE-2012-6708");

  script_name(english:"JQuery < 1.9.0 XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version in the script, the
version of JQuery hosted on the remote web server is 
prior to 1.9.0. It is, therefore, affected by a cross site
scripting vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2012-6708");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JQuery version 1.9.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-6708");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jquery_detect.nasl");
  script_require_keys("Settings/ParanoidReport", "installed_sw/jquery");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

appname = "jquery";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:8081);
app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [{"fixed_version":"1.9.0"}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING,flags:{xss:TRUE});
