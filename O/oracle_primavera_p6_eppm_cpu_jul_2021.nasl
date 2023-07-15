#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151892);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-2366", "CVE-2021-2386");
  script_xref(name:"IAVA", value:"2021-A-0347");

  script_name(english:"Oracle Primavera P6 Enterprise Project Portfolio Management (Jul 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 17.12, 18.8, 19.12, and 20.12 versions of Primavera P6 Enterprise Project Portfolio Management installed
on the remote host are affected by multiple vulnerabilities as referenced in the July 2021 CPU advisory.

  - Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction
    and Engineering (component: Web Access). Supported versions that are affected are 17.12.0-17.12.20,
    18.8.0-18.8.23, 19.12.0-19.12.14 and 20.12.0-20.12.3. Easily exploitable vulnerability allows low
    privileged attacker with network access via HTTP to compromise Primavera P6 Enterprise Project Portfolio
    Management. While the vulnerability is in Primavera P6 Enterprise Project Portfolio Management, attacks
    may significantly impact additional products. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Primavera P6 Enterprise Project Portfolio
    Management accessible data as well as unauthorized read access to a subset of Primavera P6 Enterprise
    Project Portfolio Management accessible data. (CVE-2021-2366)

  - Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction
    and Engineering (component: Web Access). Supported versions that are affected are 20.12.0-20.12.3. Easily
    exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise
    Primavera P6 Enterprise Project Portfolio Management. Successful attacks of this vulnerability can result
    in unauthorized read access to a subset of Primavera P6 Enterprise Project Portfolio Management accessible
    data. (CVE-2021-2386)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2366");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_p6_enterprise_project_portfolio_management");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '17.12.0', 'max_version' : '17.12.20', 'fixed_version' : '17.12.20.1' },
  { 'min_version' : '18.8.0', 'max_version' : '18.8.23', 'fixed_version' : '18.8.24.0' },
  { 'min_version' : '19.12.0', 'max_version' : '19.12.14', 'fixed_version' : '19.12.15.0' },
  { 'min_version' : '20.12.0', 'max_version' : '20.12.3', 'fixed_version' : '20.12.4.0' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);