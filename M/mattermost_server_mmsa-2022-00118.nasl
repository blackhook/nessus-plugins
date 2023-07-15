#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168350);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2022-4019");

  script_name(english:"Mattermost Server < 7.1.4 / 7.2.x < 7.2.1 / 7.3.x < 7.3.1 DoS (MMSA-2022-00118)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Mattermost Server running on the remote host is prior to 7.1.4, 7.2.x prior to 7.2.1, or 7.3.x prior to
7.3.1. It is, therefore, affected by a denial of service (DoS) vulnerability. An authenticated, remote attacker can
crash the server via multiple large requests to one of the Playbooks API endpoints.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mattermost.com/security-updates/");
  script_set_attribute(attribute:"see_also", value:"https://hackerone.com/reports/1685979");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mattermost Server version 7.1.4, 7.2.1, 7.3.1  or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4019");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mattermost:mattermost_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mattermost_server_detect.nbin");
  script_require_keys("installed_sw/Mattermost Server");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80);

var app_info = vcf::get_app_info(app:'Mattermost Server', port:port, webapp:TRUE);

var constraints = [
  { 'fixed_version' : '7.1.4' },
  { 'min_version' : '7.2', 'fixed_version' : '7.2.1' },
  { 'min_version' : '7.3', 'fixed_version' : '7.3.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
