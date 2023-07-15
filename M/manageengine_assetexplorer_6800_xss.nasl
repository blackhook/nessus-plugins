#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148430);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/18");

  script_cve_id("CVE-2021-20080");

  script_name(english:"ManageEngine AssentExplorer < 6.8 Unauthenticated Stored XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"A stored cross-site scripting (XSS) vulnerability exists in the XML processing logic of asset discovery. By sending a 
crafted HTTP POST request to /discoveryServlet/WsDiscoveryServlet, a remote, unauthenticated attacker can create an
asset containing malicious JavaScript. When an administrator views this asset, the JavaScript will execute. This can be
exploited to perform authenticated application actions on behalf of the administrator user.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/products/asset-explorer/sp-readme.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine AssetExplorer version 6.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20080");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoho:manageengine_assetexplorer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_assetexplorer_detect.nasl");
  script_require_keys("installed_sw/ManageEngine AssetExplorer");

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras_zoho.inc');

var appname = 'ManageEngine AssetExplorer';
var port = get_http_port(default:8080);

var app_info = vcf::zoho::fix_parse::get_app_info(app:appname, port:port);

var constraints = [
  {'fixed_version': '6800', 'fixed_display' : '6.8 Build 6800'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);

