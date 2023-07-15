#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173708);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2022-24669", "CVE-2022-24670");
  script_xref(name:"IAVA", value:"2023-A-0159");

  script_name(english:"ForgeRock Access Management 6.0.0.x / 6.5.0.x / 6.5.2.x / 6.5.3 / 6.5.4 / 7.0.x / 7.1 / 7.1.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"ForgeRock Access Management is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ForgeRock Access Management detected on the remote host is affected by multiple vulnerabilities,
including the following:
  
  - It may be possible to gain some details of the deployment through a well-crafted attack. This may allow that data to
    be used to probe internal network services. (CVE-2022-24669)

  - An attacker can use the unrestricted LDAP queries to determine configuration entries (CVE-2022-24670)

  - A cross site scripting (XSS) vulnerability which could lead to session hijacking or phishing.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://backstage.forgerock.com/knowledge/kb/article/a90639318#3M7t8j");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ForgeRock Access Management version 6.5.5, 7.1.2, 7.2 or later, or apply a patch or workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24670");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:forgerock:access_management");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:forgerock:openam");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("forgerock_access_management_web_detect.nbin");
  script_require_keys("installed_sw/ForgeRock Access Management");
  script_require_ports("Services/www", 80, 443, 8080, 8443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var app = 'ForgeRock Access Management';
var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, webapp:TRUE, port:port);

# 7.0.2, 6.5.4 have patches - requiring paranoia for just these versions. Some of these vulns have workarounds but not
# others so I won't add paranoia in general.
# Affected: AM 6.0.0.x, 6.5.0.x, 6.5.1, 6.5.2.x, 6.5.3, 6.5.4, 7.0.x, 7.1 and 7.1.1
# Fixed: AM 6.5.5, AM 7.1.2, AM 7.2
# See vendor advisory for all due to patches, workarounds, and fix
var constraints = [
  {'min_version' :  '6.0.0', 'fixed_version' : '6.0.1',  'fixed_display' : 'See vendor advisory' },
  {'min_version' :  '6.5.0', 'fixed_version' : '6.5.0.99999',  'fixed_display' : 'See vendor advisory' },
  {'equal' :  '6.5.1', 'fixed_display' : 'See vendor advisory' },
  {'min_version' :  '6.5.2', 'fixed_version' : '6.5.2.99999',  'fixed_display' : 'See vendor advisory' },
  {'equal' :  '6.5.3', 'fixed_display' : 'See vendor advisory' },
  {'equal' :  '6.5.4', 'fixed_display' : 'See vendor advisory', 'require_paranoia':TRUE },
  {'min_version' :  '7.0', 'fixed_version' : '7.0.1.9999',  'fixed_display' : 'See vendor advisory' },
  {'equal' :  '7.0.2', 'fixed_display' : 'See vendor advisory', 'require_paranoia':TRUE},
  {'min_version' :  '7.0.2.1', 'fixed_version' : '7.0.9999',  'fixed_display' : 'See vendor advisory' },
  {'equal' :  '7.1', 'fixed_display' : 'See vendor advisory' },
  {'equal' :  '7.1.1', 'fixed_display' : 'See vendor advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
