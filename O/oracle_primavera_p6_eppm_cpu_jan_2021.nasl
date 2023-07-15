#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145245);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-5421");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Primavera P6 Enterprise Project Portfolio Management (Jan 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)
installation running on the remote web server is 16.2.x through 16.2.20.0, 17.12.x through 17.12.19, 18.8.x through
18.8.21, 19.12.1.x prior to 19.12.10. It is, therefore, affected by a vulnerability as referenced in the January
2021 CPU advisory.:

  - Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction
    and Engineering (component: Web access (Spring Framework)). Supported versions that are affected are
    16.1.0 through 16.2.20, 17.1.0 through 17.12.19, 18.1.0 through 18.8.21 and 19.12.0 through 19.12.10.
    Difficult to exploit vulnerability allows low privileged attacker with network access via HTTP to compromise
    Primavera P6 Enterprise Project Portfolio Management. Successful attacks require human interaction from a
    person other than the attacker and while the vulnerability is in Primavera P6 Enterprise Project Portfolio
    Management, attacks may significantly impact additional products. Successful attacks of this vulnerability
    can result in unauthorized creation, deletion or modification access to critical data or all Primavera P6
    Enterprise Project Portfolio Management accessible data as well as unauthorized read access to a subset of
    Primavera P6 Enterprise Project Portfolio Management accessible data.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5421");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_p6_enterprise_project_portfolio_management");
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

port = get_http_port(default:8004);
get_kb_item_or_exit('www/weblogic/' + port + '/installed');

app_info = vcf::get_app_info(app:'Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)', port:port);


constraints = [
  { 'min_version' : '16.1.0', 'max_version' : '16.2.20', 'fixed_version' : '16.2.21.0' },
  { 'min_version' : '17.1.0', 'max_version' : '17.12.19', 'fixed_version' : '17.12.20.0' },
  { 'min_version' : '18.1.0', 'max_version' : '18.8.21', 'fixed_version' : '18.8.22.0' },
  { 'min_version' : '19.12.0', 'max_version' : '19.12.10', 'fixed_version' : '19.12.11.0' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
