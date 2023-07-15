#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172578);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/04");

  script_cve_id("CVE-2023-26600", "CVE-2023-26601");
  script_xref(name:"IAVA", value:"2023-A-0129-S");

  script_name(english:"ManageEngine ServiceDesk Plus < 14.0 Build 14104 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine ServiceDesk Plus running on the remote host is prior to 14.0 Build 14104. 
It is, therefore, affected by multiple vulnerabilities, including the following:

  - A Denial of Service vulnerability in image upload allows an attacker to exploit the way an API method allocates 
    memory by sending a small image file with a large size defined in the header, causing the application to crash 
    or become unresponsive. (CVE-2023-26601)

  - Privilege escalation vulnerability in query reports allows an attacker to gain access to restricted data in a 
    Postgres database system by utilizing a certain PostgreSQL function in the query, allowing the validation 
    process to be bypassed. (CVE-2023-26600)

Note that Nessus has not tested for these issues but has instead relied only on the application's
self-reported version number.");
  # https://www.manageengine.com/products/service-desk/CVE-2023-26600.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb990e39");
  # https://www.manageengine.com/products/service-desk/CVE-2023-26601.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e27c2350");
  # https://www.manageengine.com/products/service-desk/on-premises/readme.html#readme140
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3bf854f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ServiceDesk Plus version 14.0 Build 14001, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26600");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_servicedesk_plus");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

var constraints = [
  {'fixed_version': '14.1.14104', 'fixed_display': '14.1 Build 14104'}  
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);