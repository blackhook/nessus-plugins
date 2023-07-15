#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(141641);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2015-1832",
    "CVE-2017-9096",
    "CVE-2018-17196",
    "CVE-2019-17558",
    "CVE-2020-9488",
    "CVE-2020-9489"
  );
  script_bugtraq_id(93132, 109139);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Primavera Unifier (Oct 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 16.1-16.2, 17.7-17.12, 18.8, and 19.12 versions of Primavera Unifier installed on the remote host are affected by
multiple vulnerabilities as referenced in the October 2020 CPU advisory.

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Platform
    (Apache Derby)). Supported versions that are affected are 16.1-16.2, 17.7-17.12, 18.8 and 19.12. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Primavera Unifier. Successful attacks of this vulnerability can result in unauthorized access to critical
    data or complete access to all Primavera Unifier accessible data and unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of Primavera Unifier. (CVE-2015-1832)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Platform
    (iText)). Supported versions that are affected are 16.1-16.2, 17.7-17.12, 18.8 and 19.12. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Primavera Unifier. Successful attacks require human interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in takeover of Primavera Unifier. (CVE-2017-9096)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Platform
    (Apache Solr)). Supported versions that are affected are 16.1-16.2, 17.7-17.12, 18.8 and 19.12. Difficult
    to exploit vulnerability allows low privileged attacker with network access via HTTP to compromise
    Primavera Unifier. Successful attacks of this vulnerability can result in takeover of Primavera Unifier.
    (CVE-2019-17558)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9096");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-1832");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Solr Remote Code Execution via Velocity Template');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_unifier");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_unifier.nbin");
  script_require_keys("installed_sw/Oracle Primavera Unifier", "www/weblogic");
  script_require_ports("Services/www", 8002);

  exit(0);
}

include('vcf.inc');
include('http.inc');

get_install_count(app_name:'Oracle Primavera Unifier', exit_if_zero:TRUE);

port = get_http_port(default:8002);
get_kb_item_or_exit('www/weblogic/' + port + '/installed');

app_info = vcf::get_app_info(app:'Oracle Primavera Unifier', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '16.1', 'fixed_version' : '16.2.16.3' },
  { 'min_version' : '17.7', 'fixed_version' : '17.12.11.5' },
  { 'min_version' : '18.8', 'fixed_version' : '18.8.18' },
  { 'min_version' : '19.12', 'fixed_version' : '19.12.10' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);