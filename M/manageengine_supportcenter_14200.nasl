#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175100);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/13");

  script_cve_id("CVE-2023-29443");
  script_xref(name:"IAVA", value:"2023-A-0229-S");

  script_name(english:"ManageEngine SupportCenter Plus < 14.2 Build 14200 XXE");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by an XML external entity vulnerability.");
  script_set_attribute(attribute:"description", value:
"An XML external entity vulnerability exists in ManageEngine SupportCenter Plus prior to 14.2 
Build 14200. A threat actor with the SDAdmin role can configure a malicious server to return 
a response with a malformed XML using the Reports integration API, causing an XML External 
Entity (XXE) attack.

Note that Nessus has not tested for these issues but has instead relied only on the application's
self-reported version number.");
  # https://www.manageengine.com/products/service-desk/CVE-2023-29443.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fefbe388");
  # https://www.manageengine.com/products/support-center/readme.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2a6242a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine SupportCenter Plus version 14.2 Build 14200, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29443");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:supportcenter_plus");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 Tenable, Inc.");

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
  {'fixed_version': '14200', 'fixed_display' : '14.2 Build 14200'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);

