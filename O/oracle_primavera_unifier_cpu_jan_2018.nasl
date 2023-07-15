#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106201);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-2620");
  script_bugtraq_id(102583);

  script_name(english:"Oracle Primavera Unifier Platform Component Unspecified Remote Issue (January 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
an unspecified remote issue in the platform component.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera
Unifier installation running on the remote web server is missing the
January 2018 Critical Patch Update. It is, therefore, affected by an
unspecified issue in the platform component as described in the
advisory.");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html#AppendixPVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?978869a0");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2018 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2620");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_unifier");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 Tenable Network Security, Inc.");

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

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "10", "fixed_version" : "10.1.23.5" },
  { "min_version" : "15", "fixed_version" : "15.2.15.1" },
  { "min_version" : "16", "fixed_version" : "16.2.11.2" },
  { "min_version" : "17", "fixed_version" : "17.12" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

