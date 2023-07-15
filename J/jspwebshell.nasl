#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87501);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"jspwebshell Backdoor Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP backdoor script.");
  script_set_attribute(attribute:"description", value:
"At least one instance of jspwebshell is hosted on the remote web
server.  This is a JSP script that acts as a backdoor and provides
a convenient set of tools for attacking the affected host.");
  script_set_attribute(attribute:"solution", value:
"Remove any instances of the jspwebshell backdoor script and conduct a
forensic examination to determine how it was installed as well as
whether other unauthorized changes were made.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/JSP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("http.inc");

get_kb_item_or_exit("www/JSP");

port = get_http_port(default:80);

# Loop through files.
#
# nb: By default, we'll look for it as 'jspwebshell.jsp', and
#     'jspwebshell12.jsp' and, if thorough tests are enabled, some other
#     common variants. Still, the script can be named anything and
#     won't necessarily be found by webmirror.nasl so a remote check
#     is not likely to be 100% effective.
files = make_list(
  'jspwebshell.jsp',
  'jspwebshell12.jsp'
);
if (thorough_tests)
{
  files = make_list(
    files,
    'index.jsp'
  );
}

dirs = get_kb_list("www/"+port+"/content/directories");
if (isnull(dirs)) dirs = cgi_dirs();

info = "";
foreach dir (list_uniq("", dirs))
{
  foreach file (files)
  {
    url = dir + '/' + file;
    res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
    if ( res[2] && '<title>JspWebShell By ' >< res[2] )
    {
      info += '  - ' + build_url(port:port, qs:file) + '\n';

      if (!thorough_tests) break;
    }
  }
  if (info && !thorough_tests) break;
}


# Report findings.
if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 1) s = 's';
    else s = '';

    report = '\n' +
      'Nessus discovered the following instance' + s + ' of jspwebshell :\n' +
      '\n' +
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else audit(AUDIT_NOT_DETECT, "jspwebshell", port);
