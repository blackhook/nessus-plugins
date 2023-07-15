#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##


include('deprecated_nasl_level.inc');
include('compat.inc');


if (description)
{
  script_id(58976);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/23");

  script_bugtraq_id(53019);
  script_xref(name:"EDB-ID", value:"18745");

  script_name(english:"ManageEngine SupportCenter Plus < 7.9 Build 7905 Multiple Vulnerabilities");
  script_summary(english:"Checks version of ManageEngine SupportCenter Plus");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a web application affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of ManageEngine SupportCenter
Plus less than 7.9 build 7905.  Such versions are affected by multiple
vulnerabilities:

  - A SQL injection vulnerability in the 'countSql' 
    parameter of the '/servlet/AJaxServlet' script.

  - Multiple stored cross-site scripting vulnerabilities 
    that can be exploited by both authenticated and 
    anonymous users.

  - A vulnerability that allows any authenticated user to 
    delete SupportCenter backups.

  - A vulnerability that allows any authenticated user to 
    schedule and write a backup file to a publicly 
    accessible directory."
  );
  script_set_attribute(attribute:"see_also", value:"https://supportcenter.wiki.zoho.com/ReadMe-V2.html#7905");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to ManageEngine SupportCenter version 7.9 build 7905 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on an in-depth analysis of the vulnerabilities.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:supportcenter_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

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
  {'fixed_version': '7905', 'fixed_display' : '7.9 Build 7905'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE, 'sqli':TRUE}
);

