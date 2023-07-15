#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135277);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/09");

  script_cve_id("CVE-2019-1574");
  script_bugtraq_id(107900);

  script_name(english:"Palo Alto Expedition < 1.1.13 Cross-Site Scripting Vulnerability (PAN-SA-2019-0009)");

  script_set_attribute(attribute:"synopsis", value:
"The reported version of Palo Alto Expedition is vulnerable to Cross-Site Scripting.");
  script_set_attribute(attribute:"description", value:
"A cross-site scripting (XSS) vulnerability exists in Palo ALto Expedition Migration Tool due to improper validation of
user-supplied input before returning it to users. An authenticated, remote attacker can exploit this, by convincing a
user to click a specially crafted URL, to execute arbitrary script code in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"https://security.paloaltonetworks.com/CVE-2019-1574");
  script_set_attribute(attribute:"solution", value:
"Update to Palo Alto Expedition version 1.1.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1574");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:paloaltonetworks:expedition_migration_tool");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_expedition_web_detect.nbin");
  script_require_keys("installed_sw/Palo Alto Expedition");

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:443);
app_info = vcf::get_app_info(app:'Palo Alto Expedition', port:port);

if (!app_info['version']) audit(AUDIT_UNKNOWN_APP_VER, "Palo Alto Expedition");

constraints = [{'fixed_version' : '1.1.13'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE,
  flags: {xss:true}
);
