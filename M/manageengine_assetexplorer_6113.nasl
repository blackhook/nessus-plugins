#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86804);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/18");

  script_cve_id("CVE-2015-2169", "CVE-2015-5061");
  script_bugtraq_id(75389, 75411);
  script_xref(name:"EDB-ID", value:"37395");

  script_name(english:"ManageEngine AssetExplorer < 6.1.0 Build 6113 Multiple XSS");
  script_summary(english:"Checks the version of ManageEngine AssetExplorer.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple cross-site scripting
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine AssetExplorer running on the remote host
is prior to 6.1.0 build 6113. It is, therefore, affected by multiple
cross-site scripting (XSS) vulnerabilities :

  - A cross-site scripting vulnerability exists due to
    improper validation of input to the Publisher name
    before returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in the user's
    browser session. (CVE-2015-2169)

  - A cross-site scripting vulnerability exists in the
    VendorDef.do script due to improper validation of input
    to the 'organizationName' POST parameter before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in the user's
    browser session. (CVE-2015-5061)");
  # https://www.manageengine.com/products/asset-explorer/sp-readme.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e82c118");
  script_set_attribute(attribute:"solution", value:
"Upgrade ManageEngine AssetExplorer to version 6.1.0 build 6113 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on an in-depth analysis of the vulnerabilities.");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoho:manageengine_assetexplorer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'fixed_version': '6113', 'fixed_display' : '6.1 Build 6113'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);

