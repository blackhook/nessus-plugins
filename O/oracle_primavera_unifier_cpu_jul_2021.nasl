#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151973);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-5258",
    "CVE-2020-25649",
    "CVE-2020-36189",
    "CVE-2021-27807",
    "CVE-2021-27906",
    "CVE-2021-31811"
  );
  script_xref(name:"IAVA", value:"2020-A-0321");
  script_xref(name:"IAVA", value:"2021-A-0347");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Primavera Unifier (Jul 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 17.12, 18.8, 19.12, and 20.12 versions of Primavera Unifier installed on the remote host are affected by multiple
vulnerabilities as referenced in the July 2021 CPU advisory.

  - Security-in-Depth issue in the Oracle Spatial and Graph Network Data Model (jackson-databind) component of
    Oracle Primavera Unifier. (CVE-2020-36189)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Core
    (Apache PDFbox)). Supported versions that are affected are 17.7-17.12, 18.8, 19.12 and 20.12. Easily
    exploitable vulnerability allows unauthenticated attacker with logon to the infrastructure where Primavera
    Unifier executes to compromise Primavera Unifier. Successful attacks require human interaction from a
    person other than the attacker. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of Primavera Unifier.
    (CVE-2021-27906)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Core UI
    (dojo)). Supported versions that are affected are 17.7-17.12, 18.8, 19.12 and 20.12. Easily exploitable
    vulnerability allows low privileged attacker with network access via HTTP to compromise Primavera Unifier.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of Primavera Unifier accessible data. (CVE-2020-5258)

  - Security-in-Depth issue in the Oracle Spatial and Graph Network Data Model (jackson-databind) component of
    Oracle Database Server. This vulnerability cannot be exploited in the context of this product.
    (CVE-2020-25649)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36189");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/22");

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
  { 'min_version' : '17.7', 'fixed_version' : '17.12.11.8' },
  { 'min_version' : '18.8', 'fixed_version' : '18.8.18.6' },
  { 'min_version' : '19.12', 'fixed_version' : '19.12.15' },
  { 'min_version' : '20.12', 'fixed_version' : '20.12.7' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
