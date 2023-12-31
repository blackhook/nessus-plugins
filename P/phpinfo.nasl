#%NASL_MIN_LEVEL 70300
#
# This script was written by Randy Matz <rmatz@ctusa.net>
#
# Improvement by rd: look in every dir for info.php and phpinfo.php
# not just in cgi-bin

# Changes by Tenable:
# - Revised plugin title (4/24/2009)
# - Added parsing of PHP version and setting of KB items (8/30/2013)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11229);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"Web Server info.php / phpinfo.php Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to an
information disclosure attack.");
  script_set_attribute(attribute:"description", value:
"Many PHP installation tutorials instruct the user to create a PHP file
that calls the PHP function 'phpinfo()' for debugging purposes. 
Various PHP applications may also include such a file.  By accessing
such a file, a remote attacker can discover a large amount of
information about the remote web server, including :

  - The username of the user who installed PHP and if they
    are a SUDO user.

  - The IP address of the host.

  - The version of the operating system.

  - The web server version.

  - The root directory of the web server. 

  - Configuration information about the remote PHP 
    installation.");
  script_set_attribute(attribute:"solution", value:
"Remove the affected file(s).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"score from an analysis done by Tenable");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2022 Randy Matz");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80, embedded:TRUE);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if (thorough_tests)
 dirs = get_kb_list("www/" + port + "/content/directories");
else
  dirs = cgi_dirs();
if(isnull(dirs))dirs = make_list("");
else dirs = list_uniq(make_list("", dirs));

rep = NULL;
foreach dir (dirs)
{
 foreach script (make_list("/phpinfo.php", "/info.php"))
 {
   item = dir + script;
   req = http_get(item:item, port:port);
   res = http_keepalive_send_recv(port:port, data:req);
   if( res == NULL ) exit(0);
   if(res =~ "<title>(PHP [0-9.]+ - )?phpinfo\(\)<\/title>")
   {
     rep += '  - ' + build_url(port:port, qs:dir+script) + '\n';
     version = pregmatch(pattern:"\>PHP Version (.+)\<", string:res);
     if (!isnull(version))
     {
       version = version[1];
       set_kb_item(
         name  : "www/phpinfo/"+port+"/version/"+version,
         value : 'under ' + build_url(qs:dir+script, port:port)
       );
     }
   }
 }
}


if(rep != NULL)
{
 if (report_verbosity)
 {
  if (max_index(split(rep)) > 1) s = "s that call";
  else s = " that calls";

  report =
   '\n' +
   'Nessus discovered the following URL' + s + ' phpinfo() :\n' +
   '\n' +
   rep;
  security_warning(port:port, extra:report);
 }
 else security_warning(port);
}
