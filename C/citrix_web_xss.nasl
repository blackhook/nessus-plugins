#%NASL_MIN_LEVEL 70300
#
# This script was written by Michael J. Richardson <michael.richardson@protiviti.com>
#

# Changes by Tenable:
# - Revised plugin title (10/12/09)
# - Revised plugin description- fixed typo (06/03/2011)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(12301);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2003-1157");
  script_bugtraq_id(8939);

  script_name(english:"Citrix MetaFrame XP login.asp NFuse_Message Parameter XSS");

  script_set_attribute(attribute:"synopsis", value:
"The web application running on the remote host has a cross-site
scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote server is running a Citrix Web Interface server that 
is vulnerable to cross-site scripting.  When a user fails to 
authenticate, the Citrix Web Interface includes the error message 
text in the URL.  The error message can be tampered with to 
perform a cross-site scripting attack.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2003/Oct/336");
  script_set_attribute(attribute:"see_also", value:"https://resources.sei.cmu.edu/library/asset-view.cfm?assetID=52451");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Web Interface 2.1 or newer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:web_interface");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Michael J. Richardson");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_keys("www/ASP");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80, embedded:TRUE);

if(get_kb_item(string("www/", port, "/generic_xss"))) 
  exit(0);


function check(url)
{
   local_var req, res;
   req = http_get(item:string(url, "/login.asp?NFuse_LogoutId=&NFuse_MessageType=Error&NFuse_Message=<SCRIPT>alert('Ritchie')</SCRIPT>&ClientDetection=ON"), port:port);
   res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
   if ( res == NULL ) exit(0);

   if(ereg(pattern:"^HTTP/[0-9]\.[0-9] +200 ", string:res) && "<SCRIPT>alert('Ritchie')</SCRIPT>" >< res)
      {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
      } 
}

check(url:"/citrix/nfuse/default");
check(url:"/citrix/MetaframeXP/default");
