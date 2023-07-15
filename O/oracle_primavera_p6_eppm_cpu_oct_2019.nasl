#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130059);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2017-12626", "CVE-2019-2976", "CVE-2019-3020");
  script_xref(name:"IAVA", value:"2019-A-0380");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM) Multiple Vulnerabilities (Oct 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)
installation running on the remote web server is 15.x prior to 15.2.18.7, 16.x prior to 16.2.19.1, 17.x prior to
17.12.15.0, or 18.8.x prior to 18.8.14.0. It is, therefore, affected by multiple vulnerabilities:

  - A authorization vulnerability exists in Primavera P6 Enterprise Project Portfolio Management. An unauthenticated
    remote attacker can exploit this via HTTP to access controlled information on the network and EPPM.
    (CVE-2019-3020)

  - A authorization vulnerability exists in Primavera P6 Enterprise Project Portfolio Management. An authenticated remote
    attacker with low privilages can exploit this via HTTP to access controlled information on the network and EPPM.
    (CVE-2019-2976)

  - Denial of service (DDoS) vulnerability exists in Primavera P6 Enterprise Project Portfolio Management due to Out of
    Memory Exceptions while prasing documents. (CVE-2017-12626)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html#AppendixPVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7302206");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM) version
15.2.18.7 / 16.2.19.1 / 17.12.15.0 / 18.8.14.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3020");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_p6_enterprise_project_portfolio_management");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_p6_eppm.nbin");
  script_require_keys("installed_sw/Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)", "www/weblogic");
  script_require_ports("Services/www", 8004);

  exit(0);
}

include("http.inc");
include("vcf.inc");

get_install_count(app_name:"Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)", exit_if_zero:TRUE);

port = get_http_port(default:8004);
get_kb_item_or_exit("www/weblogic/" + port + "/installed");

app_info = vcf::get_app_info(app:"Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)", port:port);

constraints = [
  { "min_version" : "15.1.0.0", "fixed_version" : "15.2.18.7" },
  { "min_version" : "16.1.0.0", "fixed_version" : "16.2.19.1" },
  { "min_version" : "17.1.0.0", "fixed_version" : "17.12.15.0" },
  { "min_version" : "18.8.0.0", "fixed_version" : "18.8.14.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
