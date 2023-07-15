#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117666);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-3830");

  script_name(english:"Kibana ESA-2018-14");
  script_summary(english:"Checks the version of Kibana.");

  script_set_attribute(attribute:"synopsis", value:
"Checks the version of Kibana.");
  script_set_attribute(attribute:"description", value:
"Kibana versions 5.3.0 to 6.4.1 had a cross-site scripting (XSS)
vulnerability via the source field formatter that could allow an
attacker to obtain sensitive information from or perform destructive
actions on behalf of other Kibana users.");
  script_set_attribute(attribute:"see_also", value:"https://www.elastic.co/community/security");
  script_set_attribute(attribute:"solution", value:
"Users should upgrade to Kibana version 6.4.1 or 5.6.12. There are no
known workarounds for this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3830");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:kibana");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

constraints = [
  { "min_version" : "5.3.0", "fixed_version" : "5.6.12" },
  { "min_version" : "6.0.0", "fixed_version" : "6.4.1" }
];

flags = { 'xss':TRUE };

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:flags);
