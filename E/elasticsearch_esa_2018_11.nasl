#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112046);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-3827");

  script_name(english:"Elasticsearch ESA-2018-11");
  script_summary(english:"Checks the version of Elasticsearch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Java application that is affected by an 
unauthorised information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"A sensitive data disclosure flaw was found in the Elasticsearch
repository-azure (formerly elasticsearch-cloud-azure) plugin. When the
repository-azure plugin is set to log at TRACE level Azure credentials
can be inadvertently logged.");
  script_set_attribute(attribute:"see_also", value:"https://www.elastic.co/community/security");
  script_set_attribute(attribute:"solution", value:
"All users of Elasticsearch should upgrade to version 6.3.0. This
update will prevent the repository-azure plugin to expose Azure
credentials in Elasticsearch logs.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3827");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elastic:x-pack");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("elasticsearch_detect.nbin");
  script_require_keys("installed_sw/Elasticsearch", "Settings/ParanoidReport");
  script_require_ports("Services/www", 9200);

  exit(0);
}

include("audit.inc");
include("http.inc");
include("vcf.inc");

# We do not check if the azure cloud plugin is installed
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "Elasticsearch";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:9200);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { "fixed_version" : "6.3.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
