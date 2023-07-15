#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174552);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2022-27404");
  script_xref(name:"IAVA", value:"2023-A-0207");

  script_name(english:"Oracle Primavera P6 Enterprise Project Portfolio Management (April 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a buffer overflow vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Primavera P6 Enterprise Project Portfolio Management installed on the remote host are affected by a
buffer overflow vulnerability as referenced in the April 2023 CPU advisory.

  - Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction and 
    Engineering (component: Document Viewing using Outside In technology (FreeType)). Supported versions that are 
    affected are 18.8.0-18.8.26, 19.12.0-19.12.21, 20.12.0-20.12.18, 21.12.0-21.12.12 and 22.12.0-22.12.3. Easily 
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Primavera 
    P6 Enterprise Project Portfolio Management. Successful attacks of this vulnerability can result in takeover of 
    Primavera P6 Enterprise Project Portfolio Management. (CVE-2022-27404)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/docs/tech/security-alerts/cpuapr2023cvrf.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e8adfc4");
  # https://www.oracle.com/security-alerts/cpuapr2023.html#AppendixPVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc04a2d8");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2023 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27404");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_p6_enterprise_project_portfolio_management");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_p6_eppm.nbin");
  script_require_keys("installed_sw/Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)", "www/weblogic");
  script_require_ports("Services/www", 8004);

  exit(0);
}

include('vcf.inc');
include('http.inc');

get_install_count(app_name:'Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)', exit_if_zero:TRUE);

var port = get_http_port(default:8004);
get_kb_item_or_exit('www/weblogic/' + port + '/installed');

var app_info = vcf::get_app_info(app:'Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)', port:port);

var constraints = [
  { 'min_version' : '18.8.0.0', 'max_version' : '18.8.26.0', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '19.12.0.0', 'max_version' : '19.12.21.0', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '20.12.0.0', 'max_version' : '20.12.18.0', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '21.12.0.0', 'max_version' : '21.12.12.0', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '22.12.0.0', 'max_version' : '22.12.3.0', 'fixed_display' : 'See vendor advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
