#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46350);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"r57shell Backdoor Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP backdoor script.");
  script_set_attribute(attribute:"description", value:
"At least one instance of r57shell is hosted on the remote web server. 
This is a PHP script that acts as a backdoor and provides a convenient
set of tools for attacking the affected host.");
  script_set_attribute(attribute:"solution", value:
"Remove any instances of the script and conduct a forensic examination
to determine how it was installed as well as whether other
unauthorized changes were made.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php:TRUE);


# Loop through files.
#
# nb: By default, we'll look for it as 'r57.php' and, if thorough 
#     tests are enabled, some other common variants. Still, the
#     script can be named anything and won't necessarily be found by
#     webmirror.nasl so a remote check is not likely to be 100% 
#     effective.
files = make_list(
  'r57.php'
);
if (thorough_tests)
{
  # nb: google for 'r57shell "load average"' to see what's in use on live sites.
  files = make_list(
    files,
    'r57shell.php',
    'index.php',
    'faq.php',
    'rol.php'
  );
}

dirs = get_kb_list("www/"+port+"/content/directories");
if (isnull(dirs)) dirs = cgi_dirs();

info = "";
foreach dir (make_list(dirs))
{
  foreach file (files)
  {
    url = dir + '/' + file;
    res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
    if (
      res[2] && 
      '<b>o---[ r57shell ' >< res[2] &&
      '>Execute command on server</a> ::</div>' >< res[2]
    )
    {
      info += '  - ' + build_url(port:port, qs:url) + '\n';

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
      'Nessus discovered the following instance' + s + ' of r57shell :\n' +
      '\n' +
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else exit(0, "r57shell was not found on the web server listening on port "+port+".");
