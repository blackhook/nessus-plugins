#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121249);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-17247");

  script_name(english:"Elasticsearch ESA-2018-19");
  script_summary(english:"Checks the version of Elasticsearch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Java application that is vulnerable.");
  script_set_attribute(attribute:"description", value:
"Elasticsearch Security versions 6.5.0 and 6.5.1 contain an XXE flaw in
Machine Learnings find_file_structure API. If a policy allowing
external network access has been added to Elasticsearchs Java
Security Manager then an attacker could send a specially crafted
request capable of leaking content of local files on the Elasticsearch
node. This could allow a user to access information that they should
not have access to.Please note: by default Elasticsearch has the Java
Security Manager enabled with policies which will cause this attack to
fail.");
  # https://www.elastic.co/community/security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f00797e");
  script_set_attribute(attribute:"solution", value:
"Affected users should upgrade to Elasticsearch version 6.5.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17247");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:elasticsearch");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { "min_version" : "6.5.0", "fixed_version" : "6.5.2" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
