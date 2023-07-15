#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175414);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/15");

  script_cve_id("CVE-2023-31414", "CVE-2023-31415");
  script_xref(name:"IAVB", value:"2023-B-0031");

  script_name(english:"Elastic Kibana < 8.7.1 Arbitrary Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Java application that is affected by multiple arbitrary code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Elastic Kibana software on the remote host is missing a security update. It is, therefore, affected by
multiple arbitrary code execution vulnerabilities:

  - An attacker with All privileges to the Uptime/Synthetics feature could send a request that will attempt
    to execute JavaScript code. This could lead to the attacker executing arbitrary commands on the host
    system with permissions of the Kibana process. (CVE-2023-31415)

  - An attacker with write access to Kibana yaml or env configuration could add a specific payload that will
    attempt to execute JavaScript code. This could lead to the attacker executing arbitrary commands on the
    host system with permissions of the Kibana process. (CVE-2023-31414)

Note that Nessus has not tested for the issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://discuss.elastic.co/t/kibana-8-7-1-security-updates/332330");
  script_set_attribute(attribute:"solution", value:
"Users should upgrade to Kibana version 8.7.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-31415");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:kibana");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kibana_web_detect.nbin");
  script_require_keys("installed_sw/Kibana");
  script_require_ports("Services/www", 5601);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var app = 'Kibana';

get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:5601);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { "min_version" : "8.0.0", "fixed_version" : "8.7.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
