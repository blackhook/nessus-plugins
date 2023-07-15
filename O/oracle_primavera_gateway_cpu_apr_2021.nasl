##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148916);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2016-5725", "CVE-2020-17521");
  script_bugtraq_id(93100);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Primavera Gateway (Apr 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera Unifier installation running on the remote host
is 16.2.x, 17.12.x prior to 17.12.11. It is, therefore, affected by multiple vulnerabilities as referenced in the
April 2021 CPU advisory.

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component: Admin
    (JCraft JSch)). Supported versions that are affected are 17.12.0-17.12.10. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Primavera
    Gateway. Successful attacks of this vulnerability can result in unauthorized creation, deletion or
    modification access to critical data or all Primavera Gateway accessible data. (CVE-2016-5725)

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component: Admin
    (Apache Groovy)). Supported versions that are affected are 17.12.0-17.12.10. Easily exploitable
    vulnerability allows low privileged attacker with logon to the infrastructure where Primavera Gateway
    executes to compromise Primavera Gateway. Successful attacks of this vulnerability can result in
    unauthorized access to critical data or complete access to all Primavera Gateway accessible data.
    (CVE-2020-17521)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5725");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_gateway.nbin");
  script_require_keys("installed_sw/Oracle Primavera Gateway");
  script_require_ports("Services/www", 8006);

  exit(0);
}

include('vcf.inc');
include('http.inc');

get_install_count(app_name:'Oracle Primavera Gateway', exit_if_zero:TRUE);

var port = get_http_port(default:8006);

var app_info = vcf::get_app_info(app:'Oracle Primavera Gateway', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '16.2.0', 'max_version' : '16.2.11', 'fixed_display' : 'Please see vendor advisory' },
  { 'min_version' : '17.12.0', 'fixed_version' : '17.12.11' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
