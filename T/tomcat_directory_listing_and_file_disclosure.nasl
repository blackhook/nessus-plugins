#%NASL_MIN_LEVEL 70300
#
# written by Bekrar Chaouki - A.D.Consulting <bekrar@adconsulting.fr>
#
# Apache Tomcat Directory listing and file disclosure Vulnerabilities
#

# Changes by Tenable:
# - Revised plugin title (12/28/10)
# - Added banner check to prevent potential false positives against non-Tomcat
#   servers. (6/11/2015)

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(11438);
 script_version("1.32");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
 
 script_cve_id("CVE-2003-0042", "CVE-2003-0043");
 script_bugtraq_id(6721, 6722);
 
 script_name(english:"Apache Tomcat Directory Listing and File Disclosure");
 script_summary(english:"Apache Tomcat Directory listing and File Disclosure Bugs");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
 script_set_attribute(attribute:"description", value:
"Apache Tomcat (prior to 3.3.1a) is affected by a directory listing and
file disclosure vulnerability.

By requesting URLs containing a null character, remote attackers can
list directories even when an index.html or other file is present or
obtain unprocessed source code for a JSP file.

Also note that, when deployed with JDK 1.3.1 or earlier, Tomcat allows
files outside of the application directory to be accessed because
'web.xml' files are read with trusted privileges.");
 script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 4.1.18 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/22");
 script_set_attribute(attribute:"vuln_publication_date", value:"2003/01/25");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/03/18");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2021 A.D.Consulting");
 script_family(english:"CGI abuses");

 script_dependencies("tomcat_error_version.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("installed_sw/Apache Tomcat");

 exit(0);
}

#
# Start
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:8080, embedded:TRUE);

if(!get_port_state(port))
 exit(0, "Port " + port + " is not open.");

# Unless we're paranoid, make sure the banner looks like Tomcat.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if(banner && "Tomcat" >!< banner && "Coyote" >!< banner) exit(0, "The web server banner on port " + port + " is not Tomcat.");
}

res = http_get_cache_ka(item:"/", port:port);
if( res == NULL ) exit(0, "The Tomcat install listening on port " + port + " is not affected.");

if(("Index of /" >< res)||("Directory Listing" >< res))
  exit(0, "The Tomcat install listening on port " + port + " is not affected.");

req = str_replace(string:http_get(item:"/<REPLACEME>.jsp", port:port),
	          find:"<REPLACEME>",
		  replace:raw_string(0));

res = http_keepalive_send_recv(port:port, data:req);

if ( res == NULL )
  exit(0, "The Tomcat install listening on port " + port + " is not affected.");

if(("Index of /" >< res)||("Directory Listing" >< res))
 security_warning(port:port, extra:'By sending a malformed request, we could obtain the following listing:\n' + res);
else
  exit(0, "The Tomcat install listening on port " + port + " is not affected.");
