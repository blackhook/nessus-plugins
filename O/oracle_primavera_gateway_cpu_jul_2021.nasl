#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151974);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-17195",
    "CVE-2020-8203",
    "CVE-2020-25649",
    "CVE-2020-36189",
    "CVE-2021-21290",
    "CVE-2021-21409"
  );
  script_xref(name:"IAVA", value:"2020-A-0140");
  script_xref(name:"IAVA", value:"2021-A-0035-S");
  script_xref(name:"IAVA", value:"2021-A-0196");
  script_xref(name:"IAVA", value:"2021-A-0347");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Primavera Gateway (Jul 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 17.12.11, 18.8.11, 19.12.10, and 20.12.0 versions of Primavera Gateway installed on the remote host are affected by
multiple vulnerabilities as referenced in the July 2021 CPU advisory.

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component: Admin
    (Nimbus JOSE+JWT)). Supported versions that are affected are 18.8.0-18.8.11. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Primavera
    Gateway. Successful attacks of this vulnerability can result in takeover of Primavera Gateway.
    (CVE-2019-17195)

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component: Admin
    (Lodash)). Supported versions that are affected are 17.12.0-17.12.11, 18.8.0-18.8.11, 19.12.0-19.12.10 and
    20.12.0. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP
    to compromise Primavera Gateway. Successful attacks of this vulnerability can result in unauthorized
    creation, deletion or modification access to critical data or all Primavera Gateway accessible data and
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Primavera Gateway.
    (CVE-2020-8203)

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component: Admin
    (Netty)). Supported versions that are affected are 17.12.0-17.12.11, 18.8.0-18.8.11 and 19.12.0-19.12.10.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Primavera Gateway. Successful attacks of this vulnerability can result in unauthorized
    creation, deletion or modification access to critical data or all Primavera Gateway accessible data.
    (CVE-2021-21409)
    
  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component:
    jackson-databind). (CVE-2020-36189)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36189");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17195");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_gateway");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

var port = get_http_port(default:8006);

var app_info = vcf::get_app_info(app:'Oracle Primavera Gateway', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '17.12.0', 'max_version' : '17.12.11', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '18.8.0', 'max_version' : '18.8.11', 'fixed_version' : '18.8.12'},
  { 'min_version' : '19.12.0', 'max_version' : '19.12.10', 'fixed_version' : '19.12.11' },
  { 'min_version' : '20.12.0', 'fixed_version' : '20.12.7' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
