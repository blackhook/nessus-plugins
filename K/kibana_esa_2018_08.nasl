#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121357);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2018-3824");

  script_name(english:"Kibana ESA-2018-08");
  script_summary(english:"Checks the version of Kibana.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Java application that is vulnerable.");
  script_set_attribute(attribute:"description", value:
"X-Pack Machine Learning versions before 6.2.4 and 5.6.9 had a cross-
site scripting (XSS) vulnerability. If an attacker is able to inject
data into an index that has a ML job running against it, then when
another user views the results of the ML job it could allow the
attacker to obtain sensitive information from or perform destructive
actions on behalf of that other ML user.");
  # https://www.elastic.co/community/security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f00797e");
  script_set_attribute(attribute:"solution", value:
"Users should upgrade to Elasticsearch version 6.2.4 or 5.6.9");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3824");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:kibana");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kibana_web_detect.nbin");
  script_require_keys("installed_sw/Kibana");
  script_require_ports("Services/www", 5601);

  exit(0);
}

include("audit.inc");
include("http.inc");
include("vcf.inc");

app = "Kibana";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:5601);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

if (empty_or_null(app_info["Plugins/X-Pack/security"]))
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, app_info["path"], "X-Pack Security plugin");

constraints = [
  { "min_version" : "5.0.0", "fixed_version" : "5.6.9" },
  { "min_version" : "6.0.0", "fixed_version" : "6.2.4" }
];

flags = { 'xss':TRUE };

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:flags);
