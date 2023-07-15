#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154262);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2021-23337",
    "CVE-2021-28657",
    "CVE-2021-36090",
    "CVE-2021-36374"
  );
  script_xref(name:"IAVA", value:"2021-A-0480");

  script_name(english:"Oracle Primavera Unifier (Oct 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Primavera Unifier installed on the remote host is affected by multiple vulnerabilities as referenced in
the October 2021 CPU advisory, including the following:

  - An easily exploitable vulnerability in the File Management component of Primavera Unifier that allows an
    unauthenticated, remote attacker to compromise availability. (CVE-2021-36090)

  - An easily exploitable vulnerability in the Platform, UI (Lodash) component of Primavera Unifier that
    allows a remote, high privileged attacker to compromise confidentiality, integrity, and availability.
    (CVE-2021-23337)

  - An easily exploitable vulnerability in the Platform (Apache Tika) component of Primavera unifier that
    allows an unauthenticated attacker to compromise availability. (CVE-2021-28657)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2021.html#AppendixPVA");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23337");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_unifier");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_unifier.nbin");
  script_require_keys("installed_sw/Oracle Primavera Unifier", "www/weblogic");
  script_require_ports("Services/www", 8002);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:8002);
get_kb_item_or_exit('www/weblogic/' + port + '/installed');

var app_info = vcf::get_app_info(app:'Oracle Primavera Unifier', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '17.7', 'fixed_version' : '17.12.11.9' },
  { 'min_version' : '18.8', 'fixed_version' : '18.8.18.7' },
  { 'min_version' : '19.12', 'fixed_version' : '19.12.16' },
  { 'min_version' : '20.12', 'fixed_version' : '20.12.10' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
