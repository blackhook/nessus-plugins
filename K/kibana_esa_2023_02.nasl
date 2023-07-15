#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(174002);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2022-38778");
  script_xref(name:"IAVB", value:"2023-B-0021-S");

  script_name(english:"Kibana ESA-2023-02");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Java application that is vulnerable.");
  script_set_attribute(attribute:"description", value:
"Kibana versions before 7.17.9 and 8.6.1 have vulnerability CVE-2022-38900 in one of Kibana's implementation of 
decode-uri-component, which is vulnerable to Improper Input Validation, which could allow an authenticated attacker 
to perform a request that crashes the Kibana server process.");
  # https://discuss.elastic.co/t/elastic-7-17-9-8-5-0-and-8-6-1-security-update
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbcb2908");
  script_set_attribute(attribute:"solution", value:
"Users should upgrade to Kibana version 7.17.9 or 8.6.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38778");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/06");

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

include("http.inc");
include("vcf.inc");

app = "Kibana";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:5601);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { "min_version" : "7.0.0", "fixed_version" : "7.17.9" },
  { "min_version" : "8.0.0", "fixed_version" : "8.6.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
