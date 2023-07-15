#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132936);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2014-3596",
    "CVE-2015-9251",
    "CVE-2018-8032",
    "CVE-2019-0227",
    "CVE-2019-11358",
    "CVE-2019-12415",
    "CVE-2019-14540",
    "CVE-2019-16335"
  );
  script_bugtraq_id(
    69295,
    105658,
    107867,
    108023
  );
  script_xref(name:"IAVA", value:"2020-A-0140");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Primavera Gateway Multiple Vulnerabilities (Jan 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera Gateway installation running on the remote web
server is 15.x prior to 15.2.18, 16.x prior to 16.2.11, 17.x prior to 17.12.6, or 18.x prior to 18.8.8.1. It is,
therefore, affected by multiple vulnerabilities, including the following:

  - Two Polymorphic Typing issues present in FasterXML jackson-databind related to
    com.zaxxer.hikari.HikariDataSource which can be exploited by remote, unauthenticated attackers.
    (CVE-2019-16335, CVE-2019-14540)

  - A man-in-the-middle vulnerability caused by the getCN function in Apache Axis not properly verifying that
    the server hostname matches a domain name in the subject's Common Name (CN) or subjectAltName field of
    the X.509 certificate. An unauthenticated, remote attacker can exploit this to spoof SSL servers via a
    certificate with a subject that specifies a common name in a field that is not a CN field. (CVE-2014-3596)

  - A Server Side Request Forgery (SSRF) vulnerability in Apache Axis that can be exploited by an
    unauthenticated, remote attacker. (CVE-2019-0227)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2020.html#AppendixPVA");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2620236.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Primavera Gateway version 15.2.18 / 16.2.11 / 17.12.6 / 18.8.8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16335");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_gateway");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_gateway.nbin");
  script_require_keys("installed_sw/Oracle Primavera Gateway");
  script_require_ports("Services/www", 8006);

  exit(0);
}

include('http.inc');
include('vcf.inc');

get_install_count(app_name:'Oracle Primavera Gateway', exit_if_zero:TRUE);

port = get_http_port(default:8006);

app_info = vcf::get_app_info(app:'Oracle Primavera Gateway', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '15.0.0', 'fixed_version' : '15.2.18' },
  { 'min_version' : '16.0.0', 'fixed_version' : '16.2.11' },
  { 'min_version' : '17.0.0', 'fixed_version' : '17.12.6' },
  { 'min_version' : '18.0.0', 'fixed_version' : '18.8.8.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE});
