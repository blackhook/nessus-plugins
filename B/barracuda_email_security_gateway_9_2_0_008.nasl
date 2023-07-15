#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177587);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/25");

  script_cve_id("CVE-2023-2868");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/16");

  script_name(english:"Barracuda Email Security Gateway < 9.2.0.008 Command Injection (CVE-2023-2868)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote server is affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Barracuda Email Security Gateway on the remote web server is < 9.2.0.008.
It is, therefore, affected by a command injection vulnerability in the processing of .tar files that could allow a
remote, unauthenticated attacker to execute arbitrary commands with the privileges of the Email Security Gateway.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.barracuda.com/company/legal/esg-vulnerability");
  script_set_attribute(attribute:"see_also", value:"https://status.barracuda.com/incidents/34kx82j5n4q9");
  # https://campus.barracuda.com/product/emailsecuritygateway/doc/11141920/release-notes/#_9c1293a2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44bea323");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Barracuda Email Security Gateway 9.2.0.008 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2868");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:barracuda:email_security_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("barracuda_email_security_gateway_service_detect.nbin");
  script_require_keys("installed_sw/Barracuda Email Security Gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:'Barracuda Email Security Gateway', port:port, webapp:TRUE);

var constraints = [
  {'min_version':'5.1.3.001', 'fixed_version':'9.2.0.008'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);