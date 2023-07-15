#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132955);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id("CVE-2017-3500", "CVE-2017-3508");
  script_bugtraq_id(97881, 97883);

  script_name(english:"Oracle Primavera Gateway Multiple Vulnerabilities (Apri 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera Gateway installation running on the remote web
server is 1.x, 14.x prior to 14.2.2.0, 15.x prior to 15.2.12.0, or 16.x prior to 16.2.2.0. It is, therefore, affected by
multiple vulnerabilities in the Primavera Desktop Integration subcomponent. These vulnerabilities are easily exploitable
and allow a high privileged, remote attacker with network access via HTTP to compromise the Primavera Gateway. Attacks
can result in a takeover of the Primavera Gateway (CVE-2017-3508) or unauthorized access to data or a denial of service
(DoS) condition (CVE-2017-3500),

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2017.html#AppendixPVA");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2243231.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Primavera Gateway version 14.2.2.0 / 15.2.12.0 / 16.2.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3508");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_gateway.nbin");
  script_require_keys("installed_sw/Oracle Primavera Gateway");
  script_require_ports("Services/www", 8006);

  exit(0);
}

include('http.inc');
include('vcf.inc');

app = 'Oracle Primavera Gateway';

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8006);

app_info = vcf::get_app_info(app:app, port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '1.0.0', 'max_version' : '2.0.0', 'fixed_version' : '14.2.2.0' },
  { 'min_version' : '14.0.0', 'fixed_version' : '14.2.2.0' },
  { 'min_version' : '15.0.0', 'fixed_version' : '15.2.12.0' },
  { 'min_version' : '16.0.0', 'fixed_version' : '16.2.2.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

