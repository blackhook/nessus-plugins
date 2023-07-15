#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119460);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2015-4152");

  script_name(english:"Logstash ESA-2015-04");
  script_summary(english:"Checks the version of Logstash.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Java application that is vulnerable.");
  script_set_attribute(attribute:"description", value:
"All Logstash versions prior to 1.4.3 that use the file output plugin
are vulnerable to a directory traversal attack that allows an attacker
to write files as the Logstash user.");
  # https://www.elastic.co/community/security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f00797e");
  script_set_attribute(attribute:"solution", value:
"Users should upgrade to 1.4.3 or 1.5.0 Users that do not want to
upgrade can address the vulnerability by disabling the file output
plugin.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4152");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:logstash");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("logstash_api_detect.nbin");
  script_require_keys("installed_sw/Logstash");
  script_require_ports("Services/www", 9600);

  exit(0);
}

include("audit.inc");
include("http.inc");
include("vcf.inc");

app = "Logstash";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:9600);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { "fixed_version" : "1.4.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
