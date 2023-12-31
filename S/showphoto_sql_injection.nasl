#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(12038);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-0239");
  script_bugtraq_id(9557);

  script_name(english:"Photopost PHP Pro photo Parameter SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Photopost PHP Pro installed on the remote host fails to
sanitize user-supplied input to the 'photo' parameter of the
'showphoto.php' script before using it in a database query.  An
unauthenticated attacker may be able to exploit this issue to uncover
sensitive information, modify data, launch attacks against the
underlying database, etc.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2004/Feb/52");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch that was reportedly released to
address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/02/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:photopost:photopost_php_pro");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("photopost_detect.nasl");
  script_require_keys("www/photopost");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/photopost"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
 dir = matches[2];

 w = http_send_recv3(method:"GET", item:dir + "/showphoto.php?photo=123'", port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 res = strcat(w[0], w[1], '\r\n', w[2]);
 
 if ("id,user,userid,cat,date,title,description,keywords,bigimage,width,height,filesize,views,medwidth,medheight,medsize,approved,rating" >< res ) {
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
}
