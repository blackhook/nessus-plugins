#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105256);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-11507");

  script_name(english:"Check_MK Internal Server Error XSS");
  script_summary(english:"Checks for the product and version in the about page.");

  script_set_attribute(attribute:"synopsis", value:
"An IT monitoring application running on the remote host is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Check_MK running on the remote web server is affected 
by a reflected cross-site (XSS) scripting vulnerability in the
Internal Server Error page, due to improper encoding of error log output. 
An unauthenticated, remote attacker can exploit this to execute arbitrary 
script code in a user's browser session.");
  # https://mathias-kettner.com/check_mk-werks.php?werk_id=7661&HTML=yes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?505f8936");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Check_MK version 1.2.8p25 / 1.4.0p9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11507");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");

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

app.path = app.path + "/login.py";

res = http_send_recv3(method:"GET", item:app.path+"?output_format=<script>alert('tenable')%3b</script>", port:port);

# Implemented fix changes content type to plaintext
if (!isnull(res[1]) && !isnull(res[2]))
  if ("<script>alert('tenable');</script>" >< res[2])
    vuln = TRUE;

if(vuln)
{
  flags = make_array("xss", TRUE);
  fix = "1.2.8p25 / 1.4.0p9 or later.";
  vcf::report_results(severity:SECURITY_WARNING, fix:fix, app_info:app, flags:flags);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app.app, build_url(qs:app.path, port:app.port));
