#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166059);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2022-35405");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/10/13");

  script_name(english:"ManageEngine Access Manager Plus < 4.3 Build 4303 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an authenticated remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of ManageEngine Access Manager Plus prior to 4.3 Build 4303. 
It is, therefore, affected by an authenticated remote code execution vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.manageengine.com/products/passwordmanagerpro/advisory/rce.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4907c125");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Access Manager Plus version 4.3 Build 4303 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-35405");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Zoho Password Manager Pro XML-RPC Java Deserialization');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_access_manager_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_access_manager_plus_detect.nbin");
  script_require_keys("installed_sw/ManageEngine Access Manager Plus");
  script_require_ports("Services/www", 7272);

  exit(0);
}

include('vcf_extras_zoho.inc');
include('http.inc');

var appname = 'ManageEngine Access Manager Plus';
var port    = get_http_port(default:7272, embedded:TRUE);

var app_info = vcf::zoho::fix_parse::get_app_info(app:appname, port:port);

var constraints = [
  { 'fixed_version' : '4303', 'fixed_display' : '4.3 Build 4303' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

