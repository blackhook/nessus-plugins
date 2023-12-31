#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# This plugin uses the data collected by webmirror.nasl to try
# to download a backup file old each CGI (as in foo.php -> foo.php.old)


include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
 script_id(11411);
 script_version("1.47");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

 script_name(english:"Backup Files Disclosure");
 script_summary(english:"Attempts to download file backups");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to retrieve file backups from the remote web server.");
 script_set_attribute(attribute:"description", value:
"By appending various suffixes (ie: .old, .bak, ~, etc...) to the names
of various files on the remote host, it seems possible to retrieve
their contents, which may result in disclosure of sensitive
information.");
 # http://projects.webappsec.org/w/page/13246953/Predictable%20Resource%20Location
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f3302c6");
 script_set_attribute(attribute:"solution", value:
"Ensure the files do not contain any sensitive information, such as
credentials to connect to a database, and delete or protect those
files that should not be accessible.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/17");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2023 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("find_service1.nasl", "webmirror.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (get_kb_item('www/no404/' + port)) exit(1, "The web server on port "+port+" does not support 404 error codes.");

list = make_list();

t = get_kb_list('www/' + port + '/cgis');
if(!isnull(t))
{
  foreach c (t)
  {
    s = strstr(c, " - ");
    c = c - s;
    list = make_list(list, c);
  }
}

t = get_kb_list('www/' + port + '/content/extensions/asp');
if(!isnull(t))list = make_list(list, t);

t = get_kb_list('www/' + port + '/content/extensions/jsp');
if(!isnull(t))list = make_list(list, t);

t = get_kb_list('www/' + port + '/content/extensions/php');
if(!isnull(t))list = make_list(list, t);

t = get_kb_list('www/' + port + '/content/extensions/php3');
if(!isnull(t))list = make_list(list, t);

t = get_kb_list('www/' + port + '/content/extensions/php4');
if(!isnull(t))list = make_list(list, t);

t = get_kb_list('www/' + port + '/content/extensions/cfm');
if(!isnull(t))list = make_list(list, t);


list = make_list(list, "/.htaccess");


exts =     make_list(".old", ".bak", "~", ".copy", ".tmp", ".swp", ".1", ".~1~", "");
prefixes = make_list("",      "",    "",   "",      "",     ".",   "",   "",     "Copy%20of%20");

seen = make_array();

oldfiles = make_list();
snippets = make_array();

foreach f (list)
{
 if (f  =~ "/$" ) continue;
 if (f  == "" ) continue;
 if (f  =~ "^.*\.php\/.*$" ) f = ereg_replace(pattern:"^(.*\.php)\/.*$", replace:"\1", string:f);    # Fix for OrangeHRM's URL rewrite/routing scheme

 this_oldfiles = make_list();
 num_match = 0;
 for ( i = 0; exts[i]; i ++ )
 {
   file = ereg_replace(pattern:"(.*)/([^/]*)$", replace:"\1/" + prefixes[i] + "\2" + exts[i], string:f);
   if (seen[file]) continue;

   r = http_send_recv3(port:port, method:"GET", item:file, exit_on_fail:TRUE);
   if (r[0] =~ '^HTTP/[01]\\.[0-9] +200 ' && strlen(r[2]) > 0)
   {
      # If .htaccess, attempt to verify contents with
      # a basic set of directives that might appear
      # in a legit version of such a file.
      if (".htaccess" >< file)
      {
        if (
          "<IfModule" >!< r[2] &&
          "AddType" >!< r[2] &&
          "allow from" >!< r[2] &&
          "Allow from" >!< r[2] &&
          "AuthName" >!< r[2] &&
          "AuthType" >!< r[2] &&
          "deny from" >!< r[2] &&
          "Deny from" >!< r[2] &&
          "DirectoryIndex" >!< r[2] &&
          "ErrorDocument" >!< r[2] &&
          "order allow, deny" >!< r[2] &&
          "Order Allow, Deny" >!< r[2] &&
          "order deny, allow" >!< r[2] &&
          "Order Deny, Allow" >!< r[2] &&
          "Redirect " >!< r[2] &&
          "Require valid-user " >!< r[2] &&
          "RewriteCond" >!< r[2] &&
          "RewriteEngine" >!< r[2] &&
          "RewriteRule" >!< r[2])
          continue;
      }

    file2 = ereg_replace(pattern:"(.*)/([^/]*)$", replace:"\1/" + prefixes[i] + "\2" + exts[i], string:f + rand());
    if(!is_cgi_installed3(port:port, item:file2))
    {
     this_oldfiles = make_list(this_oldfiles, file);
     seen[file] = 1;
     num_match ++;

     snippets[file] = beginning_of_response(resp:r[2]);
    }
   }
 }
 # Avoid false positives
 if(num_match < 5) oldfiles = make_list(oldfiles, this_oldfiles);
}

n = max_index(oldfiles);
if (!n) exit(0, "No backup files were found on the web server listening on port "+port+".");

i = 0;
report = "";
if (report_verbosity > 1) x = 18;
else x = 1;

foreach f (oldfiles)
{
  report += '\n  - File' + crap(data:' ', length:x) + ': ' + f +
            '\n    URL ' + crap(data:' ', length:x) + ': ' + build_url(port:port, qs:f);
  if (report_verbosity > 1 && n < 16)
  {
    report += '\n    Response body snippet :' +
              '\n    ' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
              '\n    ' + str_replace(find:'\n', replace:'\n    ', string:snippets[f]) +
                         crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
  }
  else report += '\n';
}

if (report)
{
  if (n == 1) s = '';
  else s = 's';

  report = '\nIt is possible to read the following backup file' + s + ' :\n' + report;
  security_warning(port:port, extra:report);
  if (COMMAND_LINE) display(report);
}
