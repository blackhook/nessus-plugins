#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119422);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-17245");

  script_name(english:"Kibana ESA-2018-17");
  script_summary(english:"Checks the version of Kibana.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Java application that is vulnerable.");
  script_set_attribute(attribute:"description", value:
"Kibana versions 4.0 to 4.6, 5.0 to 5.6.12, and 6.0 to 6.4.2 contain an
error in the way authorization credentials are used when generating
PDF reports. If a report requests external resources plaintext
credentials are included in the HTTP request that could be recovered
by an external resource provider.");
  # https://www.elastic.co/blog/elastic-support-alert-kibana-reporting-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f6e8b19");
  # https://www.elastic.co/community/security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f00797e");
  script_set_attribute(attribute:"solution", value:
"Users should upgrade to Elastic Stack version 5.6.13 or 6.4.3. Users
unable to upgrade can disable the Reporting feature in Kibana by
setting xpack.reporting.enabled to false in the kibana.yml file. This
does not prevent previously leaked credentials from being reused.For
more information about mitigating from this flaw please see our blog
post.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17245");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/05");

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
  { "min_version" : "4.0", "max_version" : "4.6", "fixed_version" : "5.6.13" },
  { "min_version" : "5.0", "fixed_version" : "5.6.13" },
  { "min_version" : "6.0", "fixed_version" : "6.4.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
