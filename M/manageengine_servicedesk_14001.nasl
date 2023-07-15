#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168361);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id("CVE-2022-40771", "CVE-2022-40772");
  script_xref(name:"IAVA", value:"2022-A-0497-S");

  script_name(english:"ManageEngine ServiceDesk Plus < 14.0 Build 14001 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine ServiceDesk Plus running on the remote host is prior to 14.0 Build 14001. 
It is, therefore, affected by multiple vulnerabilities, including the following:

  - An XML external entity (XXE) vulnerability due to a flaw in the Analytics Plus integration.
    Threat actors with admin role access can retrieve local files from the server. (CVE-2022-40771)

  - A privilege escalation vulnerability allows an adversary to access restricted data in the 
    Postgres database setup by using a specific PostgreSQL function in the query, which enables 
    bypassing the validation mechanism. (CVE-2022-40772)

Note that Nessus has not tested for these issues but has instead relied only on the application's
self-reported version number.");
  # https://www.manageengine.com/products/service-desk/CVE-2022-40771.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad23e3c8");
  # https://www.manageengine.com/products/service-desk/CVE-2022-40772.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cf40def");
  # https://www.manageengine.com/products/service-desk/on-premises/readme.html#readme140
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3bf854f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ServiceDesk Plus version 14.0 Build 14001, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40772");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_servicedesk_plus");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'fixed_version': '14.0.14001', 'fixed_display': '14.0 Build 14001'}  
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
