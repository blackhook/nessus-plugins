#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174523);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2022-3748");
  script_xref(name:"IAVA", value:"2023-A-0217");

  script_name(english:"ForgeRock Access Management 7.x Improper Authorization");

  script_set_attribute(attribute:"synopsis", value:
"ForgeRock Access Management is affected by an improper authorization vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ForgeRock Access Management detected on the remote host is affected by an improper authorization 
vulnerabilty which can lead to authentication bypass, user account impersonation and account takeover. (CVE-2022-3748)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://backstage.forgerock.com/knowledge/kb/article/a34332318");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ForgeRock Access Management version 7.2.1, 7.3 or later, or apply a patch or workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3748");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:forgerock:access_management");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:forgerock:openam");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("forgerock_access_management_web_detect.nbin");
  script_require_keys("installed_sw/ForgeRock Access Management", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8080, 8443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var app = 'ForgeRock Access Management';
var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, webapp:TRUE, port:port);

# This #202301 security advisory applies to customers who have already obtained and/or applied a 202207 AM 7.x patch before February 8th, 2023.
# Making plugin paranoid since patch checking is not feasible
var constraints = [
  {'equal' :  '7.1.2', 'fixed_display' : 'See vendor advisory', 'require_paranoia':TRUE },
  {'equal' :  '7.1.3', 'fixed_display' : 'See vendor advisory', 'require_paranoia':TRUE },
  {'equal' :  '7.2.0', 'fixed_display' : 'See vendor advisory', 'require_paranoia':TRUE }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);