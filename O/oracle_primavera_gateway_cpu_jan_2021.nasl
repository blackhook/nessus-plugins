##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145223);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2020-5421", "CVE-2020-11979");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Primavera Gateway (Jan 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the January 2021 CPU advisory.

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component: Admin
    (Apache Ant)). Supported versions that are affected are 16.2.0-16.2.11 and 17.12.0-17.12.9. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Primavera Gateway. Successful attacks of this vulnerability can result in unauthorized creation, deletion
    or modification access to critical data or all Primavera Gateway accessible data. (CVE-2020-11979)

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component: Admin
    (Spring Framework)). Supported versions that are affected are 16.2.0-16.2.11, 17.12.0-17.12.9,
    18.8.0-18.8.10 and 19.12.0-19.12.10. Difficult to exploit vulnerability allows low privileged attacker
    with network access via HTTP to compromise Primavera Gateway. Successful attacks require human interaction
    from a person other than the attacker and while the vulnerability is in Primavera Gateway, attacks may
    significantly impact additional products. Successful attacks of this vulnerability can result in
    unauthorized creation, deletion or modification access to critical data or all Primavera Gateway
    accessible data as well as unauthorized read access to a subset of Primavera Gateway accessible data.
    (CVE-2020-5421)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11979");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/20");

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

port = get_http_port(default:8006);

app_info = vcf::get_app_info(app:'Oracle Primavera Gateway', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '16.2.0', 'max_version' : '16.2.11', 'fixed_display' : 'Please see vendor advisory' },
  { 'min_version' : '17.12.0', 'fixed_version' : '17.12.10' },
  { 'min_version' : '18.8.0', 'fixed_version' : '18.8.11' },
  { 'min_version' : '19.12.0', 'fixed_version' : '19.12.10.1' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);