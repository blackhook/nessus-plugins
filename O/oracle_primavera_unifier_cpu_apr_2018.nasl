#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109164);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-7525", "CVE-2017-15095");
  script_bugtraq_id(99623, 103880);

  script_name(english:"Oracle Primavera Unifier Multiple Vulnerabilities (April 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera
Unifier installation running on the remote web server is 16.x prior to
16.2.12.3 or 17.x prior to 17.12.3.0. It is, therefore, affected by 
multiple vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76507bf8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Primavera Unifier version 16.2.12.3 / 17.12.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7525");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_unifier");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_unifier.nbin");
  script_require_keys("installed_sw/Oracle Primavera Unifier", "www/weblogic");
  script_require_ports("Services/www", 8002);

  exit(0);
}

include("http.inc");
include("vcf.inc");

get_install_count(app_name:"Oracle Primavera Unifier", exit_if_zero:TRUE);

port = get_http_port(default:8002);
get_kb_item_or_exit("www/weblogic/" + port + "/installed");

app_info = vcf::get_app_info(app:"Oracle Primavera Unifier", port:port);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "16.0.0.0", "fixed_version" : "16.2.12.3" },
  { "min_version" : "17.0.0.0", "fixed_version" : "17.12.3.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE); 

