#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112037);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2017-8449");

  script_name(english:"Elasticsearch ESA-2017-03");
  script_summary(english:"Checks the version of Elasticsearch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Java application that is affected by an 
unauthorised information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"When merging multiple rules with field level security rules for the
same index, X-Pack Security 5.2.x would allow access to more fields
than the user should have seen if the field level security rules used
a mix of grant and exclude rules.");
  script_set_attribute(attribute:"see_also", value:"https://www.elastic.co/community/security");
  script_set_attribute(attribute:"solution", value:
"Update X-Pack Security to version 5.3.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8449");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elastic:x-pack");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

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

if (empty_or_null(app_info["Plugins/X-Pack/security"]))
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, app_info['path'], "X-Pack Security plugin");

constraints = [
  { "min_version" : "5.2.0", "fixed_version" : "5.3.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
