#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101087);
  script_version("2.5");
  script_cvs_date("Date: 2018/11/28 22:47:41");

  script_cve_id(
    "CVE-2014-5338",
    "CVE-2014-5339",
    "CVE-2014-5340"
    );
  script_bugtraq_id(
    69309,
    69310,
    69312
    );

  script_name(english:"Check_MK 1.2.4 < 1.2.4p4 / 1.2.5 < 1.2.5i4 Multiple Vulnerabilities");
  script_summary(english:"Checks for the product and version in the about page.");

  script_set_attribute(attribute:"synopsis", value:
"An IT monitoring application running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Check_MK running on the remote web server is 1.2.4
prior to 1.2.4p4 or 1.2.5 prior to 1.2.5i4. It is, therefore, affected
by multiple vulnerabilities :

  - Multiple cross-site script (XSS) vulnerabilities exist
    in the multisite component, specifically within the
    render_status_icons() function in file htmllib.py and
    the ajax_action() function in file actions.py, due to
    improper validation of user-supplied input before
    returning it to users. An unauthenticated, remote
    attacker can exploit these, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2014-5338)

  - A flaw exists related to row selections that allows an
    authenticated, remote attacker to write Check_MK
    configuration (.mk) files to arbitrary locations.
    (CVE-2014-5339)

  - A flaw exists in the wato component due to using the
    insecure Python pickel API calls. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted serialized object, to execute arbitrary code.
    (CVE-2014-5340)");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/archive/1/533180/100/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Check_MK version 1.2.4p4 / 1.2.5i4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:check_mk_project:check_mk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {"min_version" : "1.2.4", "fixed_version" : "1.2.4p4"},
  {"min_version" : "1.2.5", "fixed_version" : "1.2.5i4"}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE, flags:flags);
