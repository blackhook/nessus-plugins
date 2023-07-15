#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168358);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id("CVE-2022-40770", "CVE-2022-40771");
  script_xref(name:"IAVA", value:"2022-A-0497-S");

  script_name(english:"ManageEngine SupportCenter Plus < 11.0 Build 11026 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine SupportCenter Plus prior to 11.0 Build 11026 is running on the remote 
web server. It is, therefore, affected by multiple vulnerabilities, including the following:

  - A remote code execution vulnerability due to a flaw in the Analytics Plus integration input 
    field validation. Vulnerability requires an administrator role access. (CVE-2022-40770)

  - An XML external entity (XXE) vulnerability due to a flaw in the Analytics Plus integration.
    Threat actors with admin role access can retrieve local files from the server. (CVE-2022-40771)

Note that Nessus has not tested for these issues but has instead relied only on the application's
self-reported version number.");
  # https://www.manageengine.com/products/service-desk/CVE-2022-40770.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?888eb2db");
  # https://www.manageengine.com/products/service-desk/CVE-2022-40771.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad23e3c8");
  # https://www.manageengine.com/products/support-center/readme.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2a6242a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine SupportCenter Plus version 11.0 Build 11026, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40770");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:supportcenter_plus");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 Tenable, Inc.");

  script_dependencies("manageengine_supportcenter_detect.nasl");
  script_require_keys("installed_sw/ManageEngine SupportCenter");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_zoho.inc');
include('http.inc');

var port = get_http_port(default:8080);
var appname = 'ManageEngine SupportCenter';

var app_info = vcf::zoho::fix_parse::get_app_info(app:appname, port:port);

var constraints = [
  {'fixed_version': '11026', 'fixed_display' : '11.0 Build 11026'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

