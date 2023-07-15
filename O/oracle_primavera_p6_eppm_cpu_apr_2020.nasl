#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135698);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-2594", "CVE-2020-2706");
  script_xref(name:"IAVA", value:"2020-A-0140");

  script_name(english:"Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM) Multiple Vulnerabilities (Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)
installation running on the remote web server is 16.2.x prior to 16.2.20.0, 17.12.x prior to 17.12.17.1, 18.8.x prior
to 18.8.18.2, 19.12.1.x prior to 19.12.4.0, and 20.1.x up to and including 20.2.0.0. It is, therefore, affected by
multiple vulnerabilities:

  - Primavera P6 EPPM product of Oracle Construction and Engineering is vulnerable to unauthorized read/write
    access vulnerablity. Successful attacks require human interaction from a person other than the attacker,
    and while the vulnerability is in Primavera P6 EPPM, attacks may significantly impact additional products
    and can cause a partial denial of service (partial DOS) of Primavera P6 EPPM. This issue affects the
    'Project Manager' component. (CVE-2020-2594)

  - Primavera P6 EPPM product of Oracle Construction and Engineering is vulnerable to unauthorized read/write
    access vulnerablity. Low privileged attacker with network access via HTTP can compromise Primavera P6 EPPM.
    This issue affects the 'Project Manager' component. (CVE-2020-2706)
    
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2020.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Primavera P6 Enterprise Project Portfolio Management
(EPPM) version 16.2.20.0 / 17.12.17.1 / 18.8.18.2 / 19.12.4.0 / 20.3.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2594");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_p6_enterprise_project_portfolio_management");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_p6_eppm.nbin");
  script_require_keys("installed_sw/Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)", "www/weblogic");
  script_require_ports("Services/www", 8004);

  exit(0);
}

include('http.inc');
include('vcf.inc');

get_install_count(app_name:'Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)', exit_if_zero:TRUE);

port = get_http_port(default:8004);
get_kb_item_or_exit('www/weblogic/' + port + '/installed');

app_info = vcf::get_app_info(app:'Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)', port:port);

constraints = [
  { 'min_version' : '16.2.0', 'max_version' : '16.2.19.3', 'fixed_version' : '16.2.20.0'},
  { 'min_version' : '17.12.0', 'max_version' : '17.12.17.0', 'fixed_version' : '17.12.17.1'},
  { 'min_version' : '18.8.0', 'max_version' : '18.8.18.0', 'fixed_version' : '18.8.18.2'},
  { 'min_version' : '19.12.1.0', 'max_version' : '19.12.3.0', 'fixed_version' : '19.12.4.0'},
  { 'min_version' : '20.1.0.0', 'max_version' : '20.2.0.0', 'fixed_display' : 'Please refer to vendor advisory for fix.'}
  ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);