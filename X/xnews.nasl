#%NASL_MIN_LEVEL 70300
#
# This script was written by Audun Larsen <larsen@xqus.com>
#

# Changes by Tenable:
# - Revised plugin title (4/28/09)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(12068);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2002-1656");
  script_bugtraq_id(4283);

  script_name(english:"X-News Password MD5 Hash Authentication Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
information disclosure attacks.");
  script_set_attribute(attribute:"description", value:
"X-News is a news management system, written in PHP.  X-News uses a
flat-file database to store information.  It will run on most Unix and
Linux variants, as well as Microsoft Windows operating systems. 

X-News stores user ids and passwords, as MD5 hashes, in a world-
readable file, 'db/users.txt'.  This is the same information that is
issued by X-News in cookie-based authentication credentials.  An
attacker may incorporate this information into cookies and then submit
them to gain unauthorized access to the X-News administrative account.");
  # http://web.archive.org/web/20080206115958/http://kitetoua.ifrance.com/tuto/x_holes.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d20a4b44");
  script_set_attribute(attribute:"solution", value:
"Deny access to the files in the 'db' directory through the web server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/02/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Audun Larsen");

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
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80, embedded:TRUE);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if(!can_host_php(port:port))exit(0);


if (thorough_tests) dirs = list_uniq(make_list("/x-news", "/x_news", "/xnews", "/news", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 req = http_get(item:string(dir, "/x_news.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( isnull(res) ) exit(0);

 if("Powered by <a href='http://www.xqus.com'>x-news</a> v.1\.[01]" >< res)
 {
   req2 = http_get(item:string(dir, "/db/users.txt"), port:port);
   res2 = http_keepalive_send_recv(port:port, data:req2, bodyonly:TRUE);
   if( res2 == NULL ) exit(0);
   if("|1" >< res2)
   {
      security_hole(port);
      exit(0);
   } 
  } 
}
