#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101086);
  script_version("2.6");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2014-2329", "CVE-2014-2332");
  script_bugtraq_id(66391, 66396);

  script_name(english:"Check_MK 1.2.2 < 1.2.2p3 / 1.2.3 < 1.2.3i5 Multiple Vulnerabilities");
  script_summary(english:"Checks for the product and version in the about page.");

  script_set_attribute(attribute:"synopsis", value:
"An IT monitoring application running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Check_MK running on the remote web server is 1.2.2
prior to 1.2.2p3 or 1.2.3 prior to 1.2.3i5. It is, therefore, affected
by multiple vulnerabilities :

  - Multiple cross-site script (XSS) vulnerabilities exist
    due to improper validation of user-supplied input before
    returning it to users. An unauthenticated, remote
    attacker can exploit these, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2014-2329)

  - A flaw exists that allows an authenticated, remote
    attacker to delete arbitrary files via a request to an
    unspecified link. (CVE-2014-2332)");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/531594");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/531656");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Check_MK version 1.2.2p3 / 1.2.3i5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:check_mk_project:check_mk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("check_mk_detect_webui.nbin");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");
include("vcf_extras.inc");

port = get_http_port(default:80);
app = vcf::get_app_info(app:"Check_MK", webapp:TRUE, port:port);
flags = make_array("xss", TRUE);
if (app.version !~ "^[0-9.]+(([ib][0-9]+)?(p[0-9]+)?)?$")
  audit(AUDIT_UNKNOWN_WEB_APP_VER, app.app, build_url(port:app.port, qs:app.path));
vcf::check_mk::initialize();

constraints = 
[
  {"min_version" : "1.2.2", "fixed_version" : "1.2.2p3"},
  {"min_version" : "1.2.3", "fixed_version" : "1.2.3i5"}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE, flags:flags);
