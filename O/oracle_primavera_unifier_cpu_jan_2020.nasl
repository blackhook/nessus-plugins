#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133359);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2014-3596",
    "CVE-2018-8032",
    "CVE-2019-0227",
    "CVE-2019-10088",
    "CVE-2019-10093",
    "CVE-2019-10094",
    "CVE-2019-12415",
    "CVE-2019-14540",
    "CVE-2019-16335"
  );
  script_bugtraq_id(107867);
  script_xref(name:"IAVA", value:"2020-A-0140");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Primavera Unifier Multiple Vulnerabilities (Jan 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera
Unifier installation running on the remote web server is 16.1.x or
16.2.x prior to 16.2.16.0, or 17.7.x through 17.12.x prior to
17.12.11.2, or 18.8.x prior to 18.8.15, or 19.12.x prior to
19.12.0.1. It is, therefore, affected by multiple vulnerabilities:

  - A Polymorphic Typing issue was discovered in FasterXML
    jackson-databind before 2.9.10 used in Primavera Unifier.
    (CVE-2019-14540)

  - A memory exhaustion flaw exists in Apache Tika's RecursiveParserWrapper
    versions 1.7 - 1.21 used in Primavera Unifier. (CVE-2019-10088)

  - A Server Side Request Forgery (SSRF) vulnerability affected the
    Apache Axis 1.4 distribution that was last released in 2006. Security
    and bug commits commits continue in the projects Axis 1.x Subversion
    repository, legacy users are encouraged to build from source. The
    successor to Axis 1.x is Axis2, the latest version is 1.7.9 and is
    not vulnerable to this issue. (CVE-2019-0227)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://support.oracle.com/epmos/faces/DocumentDisplay?_afrLoop=325111950546185&id=2620236.1&_afrWindowMode=0&_adf.ctrl-state=nxv3x2076_4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b244b132");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Primavera Unifier version 16.2.16.0 / 17.12.11.2 / 18.8.15 / 19.12.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14540");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_unifier");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_unifier.nbin");
  script_require_keys("installed_sw/Oracle Primavera Unifier", "www/weblogic");
  script_require_ports("Services/www", 8002);

  exit(0);
}

include('http.inc');
include('vcf.inc');

get_install_count(app_name:'Oracle Primavera Unifier', exit_if_zero:TRUE);

port = get_http_port(default:8002);
get_kb_item_or_exit('www/weblogic/' + port + '/installed');

app_info = vcf::get_app_info(app:'Oracle Primavera Unifier', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '16.1', 'fixed_version' : '16.2.16.0' },
  { 'min_version' : '17.7', 'fixed_version' : '17.12.11.2' },
  { 'min_version' : '18.8', 'fixed_version' : '18.8.15' },
  { 'min_version' : '19.12', 'fixed_version' : '19.12.0.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE); 
