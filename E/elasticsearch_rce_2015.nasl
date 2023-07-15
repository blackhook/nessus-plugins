#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105752);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2015-5377");

  script_name(english:"Elasticsearch Transport Protocol Unspecified Remote Code Execution");
  script_summary(english:"Checks the installed Elasticsearch version");

  script_set_attribute(attribute:"synopsis", value:
"Elasticsearch contains an unspecified flaw related to the transport
 protocol that may allow a remote attacker to execute arbitrary code.");
  script_set_attribute(attribute:"description", value:
"Elasticsearch could allow a remote attacker to execute arbitrary 
code on the system, caused by an error in the transport protocol. 
An attacker could exploit this vulnerability to execute arbitrary 
code on the system.");
  # https://discuss.elastic.co/t/elasticsearch-remote-code-execution-cve-2015-5377/25736
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6b6cf1a");
  script_set_attribute(attribute:"solution", value:
"Users should upgrade to 1.6.1 or 1.7.0. Alternately, ensure that only
trusted applications have access to the transport protocol port");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5377");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:elasticsearch");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("elasticsearch_detect.nbin");
  script_require_keys("installed_sw/Elasticsearch");
  script_require_ports("Services/www", 9200);

  exit(0);
}

include("audit.inc");
include("http.inc");
include("vcf.inc");

app = "Elasticsearch";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:9200);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { "min_version" : "1.0.0", "fixed_version" : "1.6.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
