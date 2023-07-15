#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101089);
  script_version("2.2");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-9781");

  script_name(english:"Check_MK < 1.4.0p6 webapi.py XSS");
  script_summary(english:"Checks for the product and version in the about page.");

  script_set_attribute(attribute:"synopsis", value:
"An IT monitoring application running on the remote host is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Check_MK running on the remote web server is prior to
1.4.0p6. It is, therefore, affected by a reflected cross-site (XSS)
scripting vulnerability in webapi.py due to error messages being
interpreted as HTML when they should be plain text. An
unauthenticated, remote attacker can exploit this to execute arbitrary
script code in a user's browser session.");
  # http://git.mathias-kettner.de/git/?p=check_mk.git;a=blob;f=.werks/4757;hb=c248f0b6ff7b15ced9f07a3df8a80fad656ea5b1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbc2935d");
  script_set_attribute(attribute:"see_also", value:"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9781");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Check_MK version 1.4.0p6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9781");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:check_mk_project:check_mk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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

port = get_http_port(default:80);
app = vcf::get_app_info(app:"Check_MK", webapp:TRUE, port:port);

app.path = app.path + "/webapi.py";

res = http_send_recv3(method:"GET", item:app.path+"?_username=<script>alert('Tenable')%3b</script>&_secret=Nessus", port:port);

# Implemented fix changes content type to plaintext
if (!isnull(res[1]) && !isnull(res[2]))
  if (res[1] =~"Content-Type: text/html" && "<script>alert('Tenable');</script>" >< res[2])
  vuln = TRUE;

if(vuln)
{
  flags = make_array("xss", TRUE);
  fix = "1.4.0p6";
  vcf::report_results(severity:SECURITY_WARNING, fix:fix, app_info:app, flags:flags);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app.app, build_url(qs:app.path, port:app.port));
