#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26058);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"lighttpd Status Module Remote Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The instance of lighttpd running on the remote host allows
unauthenticated access to URLs associated with the Status module
(mod_status), at least from the Nessus server. Mod_status reports
information about how the web server is configured and its usage, and
it may prove useful to an attacker seeking to attack the server or
host.");
  # http://web.archive.org/web/20100813022740/http://redmine.lighttpd.net/wiki/lighttpd/Docs:ModStatus
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3151c73a");
  script_set_attribute(attribute:"solution", value:
"Reconfigure lighttpd to require authentication for the affected
URL(s), restrict access to them by IP address, or disable the Status
module itself.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lighttpd:lighttpd");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2007-2022 Tenable Network Security, Inc.");

  script_dependencies("lighttpd_detect.nasl");
  script_require_keys("installed_sw/lighttpd");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");

get_install_count(app_name:"lighttpd", exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:"lighttpd", port:port);

# Try to retrieve the possible default URLs.
urls = make_list("/server-status", "/server-config", "/server-statistics");

info = "";
foreach url (urls)
{
  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer.");
  res = w[2];

  if (
    ("status" >< url     && ">Server-Status<" >< res) ||
    ("config" >< url     && ">Server-Features<" >< res) ||
    ("statistics" >< url && "fastcgi.backend." >< res)
  )
  {
    info += '  ' + url + '\n';
    if (!thorough_tests) break;
  }
}

# Report any findings.
if (info)
{
  nurls = max_index(split(info));

  report = string(
    "Nessus found ", nurls, " URL(s) associated with the Status module enabled :\n",
    "\n",
    info
  );

  if (!thorough_tests)
  {
    report = string(
      report,
      "\n",
      "Note that Nessus did not check whether there were other instances\n",
      "installed because the 'Perform thorough tests' setting was not enabled\n",
      "when this scan was run.\n"
    );
  }

  security_warning(port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "lighttpd", port, install["version"]);
