#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108541);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2007-1276");

  script_name(english:"Webmin chooser.cgi Cross-Site Scripting (< 1.330)");
  script_summary(english:"Checks the version of Webmin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a script injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Webmin installed on the remote host is older than
1.330. It is, therefore, affected by multiple cross-site scripting
(XSS) vulnerabilities in chooser.cgi. These flaws allow remote
attackers to inject arbitrary web script or HTML via a crafted
filename. Note that Nessus has relied on the self-reported version
of the sofware from either the index page or the Server header.");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/changes-1.330.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Webmin version 1.330 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webmin:webmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webmin.nasl");
  script_require_keys("www/webmin");
  script_require_ports("Services/www", 10000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'Webmin';
port = get_http_port(default:10000, embedded: TRUE);
version = get_kb_item_or_exit('www/webmin/'+port+'/version');
url = build_url(port:port, qs:'/');
fix = "1.330";

if (ver_compare(fix:"1.330", ver:version, strict:FALSE) == -1)
{
  security_report_v4(
    severity:SECURITY_WARNING,
    port:port,
    extra:
      '\n' + '  URL              : ' + url +
      '\n' + '  Reported version : ' + version +
      '\n' + '  Fixed version    : ' + fix +
      '\n',
    xss:TRUE
  );
}
else
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);
}
