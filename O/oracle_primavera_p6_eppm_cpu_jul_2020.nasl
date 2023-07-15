#%NASL_MIN_LEVEL 70300

#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138511);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-12610",
    "CVE-2018-1288",
    "CVE-2018-17196",
    "CVE-2020-10683",
    "CVE-2020-14653",
    "CVE-2020-14706"
  );
  script_bugtraq_id(109139);
  script_xref(name:"IAVA", value:"2020-A-0324");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Primavera P6 Enterprise Project Portfolio Management Multiple Vulnerabilities (Jul 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)
installation running on the remote web server is 16.1.x prior to 16.2.20.1, 17.1.x prior to 17.12.17.1, 18.1.x prior to
18.8.19, or 19.12.x prior to 19.12.6.0. It is, therefore, affected by multiple vulnerabilities as referenced in the July
2020 CPU advisory, including the following:

  - Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction
    and Engineering (component: Web Access (dom4j)). Supported versions that are affected are
    16.1.0.0-16.2.20.1, 17.1.0.0-17.12.17.1, 18.1.0.0-18.8.19 and 19.12.0-19.12.6. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Primavera P6
    Enterprise Project Portfolio Management. Successful attacks of this vulnerability can result in takeover
    of Primavera P6 Enterprise Project Portfolio Management. (CVE-2020-10683)

  - Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction
    and Engineering (component: Web Access (kafka client)). Supported versions that are affected are
    19.12.0-19.12.6. Easily exploitable vulnerability allows low privileged attacker with network access via
    HTTP to compromise Primavera P6 Enterprise Project Portfolio Management. Successful attacks of this
    vulnerability can result in takeover of Primavera P6 Enterprise Project Portfolio Management.
    (CVE-2018-17196)

  - Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction
    and Engineering (component: Web Access). Supported versions that are affected are 17.1.0.0-17.12.17.1,
    18.1.0.0-18.8.19 and 19.12.0-19.12.5. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via HTTP to compromise Primavera P6 Enterprise Project Portfolio Management. Successful
    attacks require human interaction from a person other than the attacker. Successful attacks of this
    vulnerability can result in unauthorized access to critical data or complete access to all Primavera P6
    Enterprise Project Portfolio Management accessible data as well as unauthorized update, insert or delete
    access to some of Primavera P6 Enterprise Project Portfolio Management accessible data.
    (CVE-2020-14706)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10683");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/15");

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
  { 'min_version' : '16.1.0', 'max_version' : '16.2.20.1', 'fixed_version' : '16.2.20.2'},
  { 'min_version' : '17.1.0', 'max_version' : '17.12.17.1', 'fixed_version' : '17.12.18.0'},
  { 'min_version' : '18.1.0', 'max_version' : '18.8.19.0', 'fixed_version' : '18.8.20.0'},
  { 'min_version' : '19.12.0.0', 'max_version' : '19.12.6.0', 'fixed_version' : '19.12.7.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
