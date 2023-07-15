#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176861);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/08");

  script_cve_id("CVE-2022-47966");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/02/13");

  script_name(english:"ManageEngine ServiceDesk Plus < 14.0 Build 14004 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"A remote code execution vulnerability exists in ManageEngine ServiceDesk Plus prior to 14.0 Build 14004 due to use of
Apache xmlsec (aka XML Security for Java) 1.4.1, because the xmlsec XSLT features, by design in that version, make the 
application responsible for certain security protections, and the ManageEngine applications did not provide those 
protections.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5404a809");
  # https://www.manageengine.com/products/service-desk/on-premises/readme.html#readme140
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3bf854f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ServiceDesk Plus version 14.0 Build 14004, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-47966");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ManageEngine Endpoint Central Unauthenticated SAML RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_servicedesk_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_servicedesk_detect.nasl");
  script_require_keys("installed_sw/manageengine_servicedesk");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('vcf_extras_zoho.inc');
include('http.inc');

var appname = 'ManageEngine ServiceDesk Plus';

var port = get_http_port(default:8080);
var app_info = vcf::zoho::servicedesk::get_app_info(app:appname, port:port);
var constraints;

if (!empty_or_null(app_info['SSO Login Enabled'])) 
{
  constraints = [
    {'fixed_version': '14.0.14004', 'fixed_display': '14.0 Build 14004'}  
  ];

  vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
}
else 
  audit(AUDIT_POTENTIAL_VULN, appname);