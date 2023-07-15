#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152198);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-20090", "CVE-2021-20091", "CVE-2021-20092");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Buffalo Routers Multiple Vulnerabilities (TRA-2021-13)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to determine that the remote Buffalo device is affected by multiple vulnerabilities:
  
  - A path traversal vulnerability in the web interfaces of certain Buffalo router models could 
    allow unauthenticated remote attackers to bypass authentication. (CVE-2021-20090)

  - The web interfaces of certain Buffalo router models do not properly sanitize user input. An 
    authenticated remote attacker could leverage this vulnerability to alter device configuration, 
    potentially gaining remote code execution. (CVE-2021-20091)

  - The web interfaces of certain Buffalo router models do not properly restrict access to 
    sensitive information from an unauthorized actor. (CVE-2021-20092)

Note that Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2021-13");
  script_set_attribute(attribute:"solution", value:
"Vendor has released fixes for certain models. Contact vendor for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20090");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:buffalo:buffalo");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("buffalo_www_detect.nbin");
  script_require_keys("installed_sw/Buffalo WWW");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80, embedded:TRUE);
var app_info = vcf::get_app_info(app:'Buffalo WWW', webapp:TRUE, port:port);
var constraints;

if('WSR-2533DHPL2' >< app_info.model || 'WXR-5700AX7S' >< app_info.model || 'WSR-1166DHP2' >< app_info.model )
  constraints = [{'min_version' : '0', 'fixed_display' : 'No known fix' }];
else if('WSR-A2533DHP3' >< app_info.model) 
  constraints = [{'min_version' : '0', 'fixed_version' : '1.25' }];
else if('WSR-3200AX4S' >< app_info.model)
  constraints = [{'min_version' : '0', 'fixed_version' : '1.20' }];
else
{
  var ver_model = app_info.version;
  if (!empty_or_null(app_info.model))
    ver_model = ver_model + ' (model '+app_info.model+')';
  audit(AUDIT_INST_VER_NOT_VULN, app_info.app, ver_model);
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
