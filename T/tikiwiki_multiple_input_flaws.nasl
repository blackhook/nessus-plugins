#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
 script_id(14364);
 script_version("1.27");

 script_cve_id(
   "CVE-2004-1923", 
   "CVE-2004-1924", 
   "CVE-2004-1925", 
   "CVE-2004-1926", 
   "CVE-2004-1927", 
   "CVE-2004-1928"
 );
 script_bugtraq_id(10100);
 
 script_name(english:"TikiWiki < 1.8.2 Multiple Input Validation Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running TikiWiki, a content management system
written in PHP. 

The remote version of this software has multiple vulnerabilities that
have been identified in various modules of the application.  These
vulnerabilities may allow a remote attacker to carry out various
attacks such as path disclosure, cross-site scripting, HTML injection,
SQL injection, directory traversal, and arbitrary file upload." );
  # http://web.archive.org/web/20080101124751/http://www.gulftech.org/?node=research&article_id=00037-04112004
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f6bfebe" );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2004/Apr/147" );
 script_set_attribute(attribute:"see_also", value:"https://tiki.org/tiki-read_article.php?articleId=66" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to TikiWiki 1.8.2 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/04/11");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:tikiwiki:tikiwiki");
script_end_attributes();

 
 script_summary(english:"Checks the version of TikiWiki");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80, embedded:TRUE);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
function check(loc)
{
 local_var r, req;
 req = http_get(item: loc + "/tiki-index.php", port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if( egrep(pattern:"This is Tiki v(0\.|1\.[0-7]\.|1\.8\.[0-1][^0-9])", string:r) )
 {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

