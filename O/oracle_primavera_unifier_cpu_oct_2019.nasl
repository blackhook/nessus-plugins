#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130070);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-12626",
    "CVE-2019-11358",
    "CVE-2019-12086",
    "CVE-2019-14379",
    "CVE-2019-14439"
  );
  script_bugtraq_id(102879, 108023, 109227);
  script_xref(name:"IAVA", value:"2019-A-0380");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Primavera Unifier Multiple Vulnerabilities (Oct 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera Unifier installation running on the remote web
server is 16.1.x or 16.2.x prior to 16.2.15.10, or 17.7.x through 17.12.x prior to 17.12.11.1, or 18.8.x prior to
18.8.13.0. It is, therefore, affected by multiple vulnerabilities:

    - An unspecified flaw exists in how 'default typing' is handled when 'ehcache' is used in the
      jackson-databind component of Primavera Unifier. An unauthenticated, remote attacker can exploit this
      via the network over HTTP to cause remote code execution. (CVE-2019-14379)

    - An information disclosure vulnerability exists in the jackson-databind component of Primavera Unifier.
      An unauthenticated, remote attacker can exploit this via an externally exposed JSON endpoint if the
      service has the mysql-connector-java jar in the classpath, and the attacker can host a crafted MySQL
      server accessible by the victim. An attacker can send a crafted JSON message to read arbitrary local
      files on the server. (CVE-2019-12086)

    - An information disclosure vulnerability exists in the jackson-databind component of Primavera Unifier.
      An unauthenticated, remote attacker can exploit this via an externally exposed JSON endpoint if the
      service has the logback jar in the classpath, which can allow information disclosure. (CVE-2019-14439)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b370bc74");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Primavera Unifier version 16.2.15.10 / 17.12.11.1 / 18.8.13.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14379");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_unifier");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '16.1.0.0', 'fixed_version' : '16.2.15.10' },
  { 'min_version' : '17.7.0.0', 'fixed_version' : '17.12.11.1' },
  { 'min_version' : '18.8.0.0', 'fixed_version' : '18.8.13.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE); 
