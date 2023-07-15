#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176630);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/14");

  script_cve_id("CVE-2022-24990");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/03");
  script_xref(name:"CEA-ID", value:"CEA-2023-0004");

  script_name(english:"TerraMaster TOS < 4.2.30 Command Injection (CVE-2022-24990)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote server is affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Terramaster TOS running on the remote web server is < 4.2.30.
It is, therefore, affected by a vulnerability that allows remote attackers to discover the administrative password by
sending 'User-Agent: TNAS' to module/api.php?mobile/webNasIPS and then reading the PWD field in the response.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://forum.terra-master.com/en/viewtopic.php?f=28&t=3030");
  # https://octagon.net/blog/2022/03/07/cve-2022-24990-terrmaster-tos-unauthenticated-remote-command-execution-via-php-object-instantiation/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61097558");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TerraMaster TOS 4.2.30 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24990");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'TerraMaster TOS 4.2.29 or lower - Unauthenticated RCE chaining CVE-2022-24990 and CVE-2022-24989');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:terra-master:tos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:terra-master:terramaster_operating_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("terramaster_tos_detect.nbin");
  script_require_keys("installed_sw/Terramaster TOS");
  script_require_ports("Services/www", 80, 443, 5443, 8181);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:8181);

var app_info = vcf::get_app_info(app:'Terramaster TOS', port:port, webapp:TRUE);

var constraints = [
  {'fixed_version':'4.2.30'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);