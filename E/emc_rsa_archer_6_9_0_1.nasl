##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143422);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/28");

  script_cve_id("CVE-2020-26884");
  script_xref(name:"IAVA", value:"2020-A-0546-S");

  script_name(english:"EMC RSA Archer 6.8 < 6.8.0.4 / 6.9 < 6.9.0.1 URL Injection");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by a URL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC RSA Archer running on the remote web server is 6.8.x prior to 6.8.0.4 (6.8 P4) or 6.9.x prior to
6.9.0.1 (6.9 P1). It is, therefore, affected by a URL injection vulnerability. An unauthenticated, remote attacker can
exploit this by tricking a victim application user to execute malicious JavaScript code in the context of the web
application.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://community.rsa.com/docs/DOC-114997");
  script_set_attribute(attribute:"solution", value:
"Update to 6.8.0.4, 6.9.0.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26884");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:rsa_archer_egrc");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_rsa_archer_detect.nbin");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}


include('http.inc');
include('vcf.inc');

app_name = 'EMC RSA Archer';
port = get_http_port(default:80);

app_info = vcf::get_app_info(app:app_name, webapp:TRUE, port:port);

constraints = [
  {'min_version' : '6.8', 'fixed_version' : '6.8.0.4', 'fixed_display' : '6.8 P4 (6.8.0.4)'},
  {'min_version' : '6.9', 'fixed_version' : '6.9.0.1', 'fixed_display' : '6.9 P1 (6.9.0.1)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

