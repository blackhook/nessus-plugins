#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165694);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2020-36518");

  script_name(english:"Oracle Primavera P6 Enterprise Project Portfolio Management (Jul 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The versions of Primavera P6 Enterprise Project Portfolio Management installed on the remote host are affected by a
vulnerability as referenced in the July 2022 CPU advisory.

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Centralized
    Third Party Jars (jackson-databind)). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and
    14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP
    to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle WebLogic Server.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2022 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36518");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_p6_enterprise_project_portfolio_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '17.12.0.0', 'fixed_version' : '17.12.20.5' },
  { 'min_version' : '18.8.0.0',  'fixed_version' : '18.8.25.5'  },
  { 'min_version' : '19.12.0.0', 'fixed_version' : '19.12.20.0' },
  { 'min_version' : '20.12.0.0', 'fixed_version' : '20.12.15.0' },
  { 'min_version' : '21.12.0.0', 'fixed_version' : '21.12.7.0'  }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
