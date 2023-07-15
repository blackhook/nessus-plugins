#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118798);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/19");

  script_cve_id("CVE-2018-17246");

  script_name(english:"Kibana ESA-2018-18");
  script_summary(english:"Checks the version of Kibana.");

  script_set_attribute(attribute:"synopsis", value:
"Based on its self-reported version, the remote web server hosts a 
Java application which is affected by an arbitrary file inclusion vulnerability.");
  script_set_attribute(attribute:"description", value:
"Nethanel Coppenhagen of CyberArk Labs discovered Kibana versions
before 6.4.3 and 5.6.13 contain an arbitrary file inclusion flaw in
the Console plugin. An attacker with access to the Kibana Console API
could send a request that will attempt to execute javascript code.
This could possibly lead to an attacker executing arbitrary commands
with permissions of the Kibana process on the host system.Note that
Nessus has not tested for this issue but has instead relied only on
the application's self-reported version number.");
  # https://www.elastic.co/community/security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f00797e");
  script_set_attribute(attribute:"solution", value:
"Users should upgrade to Elastic Stack version 6.4.3 or 5.6.13 or 
later. Users unable to upgrade their installations should refer to 
the mitigation instructions outlined in the vendor advisory.
");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17246");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:kibana");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { "min_version" : "5.0.0", "fixed_version" : "5.6.13" },
  { "min_version" : "6.0.0", "fixed_version" : "6.4.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
