#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(106609);
  script_version ("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/22");

  script_name(english:"Microsoft Windows IIS Default Index Page");
  script_summary(english: "Checks for the default index page.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses the default IIS index page.");
  script_set_attribute(attribute:"description", value:
"The remote web server uses the default IIS index page. This
page may contain extra version information and is an
indication of a misconfigured server.");
  script_set_attribute(attribute:"solution", value:
"Remove the default index page.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Web Servers");

  script_dependencies("http_version.nasl");
  script_require_keys("www/iis", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

if (report_paranoia < 2)
{
  audit(AUDIT_PARANOID);
}

get_kb_item_or_exit("www/iis");

app = "Microsoft IIS";
port = get_http_port(default:80);
banner = get_http_banner(port:port);
if (empty_or_null(banner) || "Server: Microsoft-IIS" >!< banner)
{
  audit(AUDIT_NOT_DETECT, app, port);
}

res = http_get_cache(port:port, item:'/');
if (("<title>IIS Windows Server</title>" >< res &&
    ('<img src="iisstart.png" alt="IIS" width="960" height="600" />' >< res ||
     '<img src="iis-85.png" alt="IIS" width="960" height="600" />' >< res)) ||
    ("<title>IIS7</title>" >< res &&
      '<img src="welcome.png" alt="IIS7" width="571" height="411" />' >< res))
{
  report = '\nThe IIS server listening on port ' + port + ' uses the\n' +
           'default index page:\n' +
           '\n' +
           build_url(qs:"/", port:port) +
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}

audit(AUDIT_LISTEN_NOT_VULN, app, port);
