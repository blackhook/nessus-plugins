#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177102);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/13");

  script_cve_id("CVE-2019-7483");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"SonicWall SMA100 Directory Traversal Vulnerability (SNWLID-2019-0018)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of SonicWall SMA100 installed on the remote host is prior 9.0.0.4. It is, therefore, affected by a
directory traversal vulnerability. In SonicWall SMA100, an unauthenticated Directory Traversal vulnerability in 
the handleWAFRedirect CGI allows the user to test for the presence of a file on the server.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2019-0018");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a SonicWall SMA version that is 9.0.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7483");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:sonicwall:firmware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_sma_web_detect.nbin");
  script_require_keys("installed_sw/SonicWall Secure Mobile Access", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var app_name = 'SonicWall Secure Mobile Access';

get_install_count(app_name:app_name, exit_if_zero:TRUE);

# We cannot test for vulnerable models
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var port = get_http_port(default:443, embedded:TRUE);

var app_info = vcf::get_app_info(app:app_name, port:port, webapp:TRUE);

var constraints = [
  {'fixed_version' : '9.0.0.4'}

];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
