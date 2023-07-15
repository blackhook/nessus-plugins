#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130019);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2017-12626", "CVE-2019-12086", "CVE-2019-14379");
  script_bugtraq_id(102879, 109227);
  script_xref(name:"IAVA", value:"2019-A-0380");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Primavera Gateway Multiple Vulnerabilities (Oct 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera Gateway installation running on the remote web
server is 15.x prior to 15.2.17, 16.x prior to 16.2.10, 17.x prior to 17.12.5, or 18.x prior to 18.8.7. It is,
therefore, affected by multiple vulnerabilities:

  - An arbitrary file read vulnerability exists in the FasterXML jackson-databind component, which is version
    2.x prior to 2.9.9. This vulnerability is due to missing com.mysql.cj.jdbc.admin.MiniAdmin validation. An
    unauthenticated, remote attacker can exploit this by hosting a crafted MySQL server reachable by the
    victim and sending a crated JSON message that allows them to read arbitrary files and disclose sensitive
    information. (CVE-2019-12086)

  - Denial of service (DoS) vulnerabilities exist in the Apache POI component, which is prior to 3.1.7, due
    to a flaw when parsing crafted WMF, EMF, MSG, macros, DOC, PPT, and XLS. An unauthenticated, remote
    attacker can exploit this issue, via sending crafted input, to cause the application to stop responding.
    (CVE-2017-12626)

  - A remote code execution vulnerability exists in the FasterXML jackson-databind component, which is prior
    to 2.9.0.2, due to a flaw in how default typing is handled when ehcache is used because of 
    net.sf.ehcache.transaction.manager.DefaultTransactionManagerLookup. An unauthenticated, remote attacker
    can exploit this to bypass authentication and execute arbitrary commands. (CVE-2019-14379)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html#AppendixPVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7302206");
  # https://support.oracle.com/rs?type=doc&id=2593049.1%20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f2e008f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Primavera Gateway version 15.2.17 / 16.2.10 / 17.12.5 / 18.8.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14379");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_gateway");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '15.0.0', 'fixed_version' : '15.2.17' },
  { 'min_version' : '16.0.0', 'fixed_version' : '16.2.10' },
  { 'min_version' : '17.0.0', 'fixed_version' : '17.12.5' },
  { 'min_version' : '18.0.0', 'fixed_version' : '18.8.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
