#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101396);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"DNN (DotNetNuke) 3.0.0 < 9.1.0 SWF File Handling XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET application that is affected
by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of DNN Platform (formerly DotNetNuke) running on the
remote host is 3.0.0 or later but prior to 9.1.0. It is, therefore,
affected by a cross-site scripting (XSS) vulnerability due to improper
validation of user-supplied input when handling SWF files. An
unauthenticated, remote attacker can exploit this, via a specially
crafted request, to execute arbitrary script code in a user's browser
session.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://www.dnnsoftware.com/community-blog/cid/155437/dnn-911-security-bulletin-released
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a950f08f");
  script_set_attribute(attribute:"see_also", value:"https://www.dnnsoftware.com/community/security/security-center");
  script_set_attribute(attribute:"solution", value:
"Upgrade to DNN Platform version 9.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_keys("installed_sw/DNN");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http.inc");
include("vcf.inc");

app = "DNN";

get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:80, asp:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
      {"min_version" : "3.0.0", "max_version" : "9.0.2", "fixed_version" : "9.1.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
