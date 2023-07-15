#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172641);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/04");

  script_cve_id("CVE-2023-26601");
  script_xref(name:"IAVA", value:"2023-A-0129-S");

  script_name(english:"ManageEngine SupportCenter Plus < 14.0 Build 14001 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine SupportCenter Plus prior to 14.0 Build 14001 is running on the remote 
web server. It is, therefore, affected by a denial of service vulnerability:

- A Denial of Service vulnerability in image upload. This vulnerability allows an
attacker to exploit the way an API method allocates memory by sending a small image
file with a large size defined in the header, causing the application to crash or
become unresponsive. (CVE-2023-26601)

Note that Nessus has not tested for these issues but has instead relied only on the application's
self-reported version number.");
  # https://www.manageengine.com/products/service-desk/CVE-2023-26601.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e27c2350");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine SupportCenter Plus version 14.0 Build 14001, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26601");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/17");

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
  {'fixed_version': '14001', 'fixed_display' : '14.0 Build 14001'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);