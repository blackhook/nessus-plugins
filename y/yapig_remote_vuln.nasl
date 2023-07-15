#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14269);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(10891);

  script_name(english:"YaPiG < 0.92.2 Multiple Scripts Arbitrary Command Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
arbitrary PHP code injection vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running YaPiG, a web-based image gallery written in
PHP. 

The remote version of YaPiG may allow a remote attacker to execute
malicious scripts on a vulnerable system.  This issue exists due to a
lack of sanitization of user-supplied data.  It is reported that an
attacker may be able to upload content that will be saved on the
server with a '.php' extension.  When this file is requested by the
attacker, the contents of the file will be parsed and executed by the
PHP engine, rather than being sent.  Successful exploitation of this
issue may allow an attacker to execute malicious script code on a
vulnerable server.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2004/Aug/802");
  script_set_attribute(attribute:"solution", value:
"Upgrade to YaPiG 0.92.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:yapig:yapig");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

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
if (!can_host_php(port:port)) exit(0);


if (thorough_tests) dirs = list_uniq(make_list("/yapig", "/gallery", "/photos", "/photo", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
	res = http_get_cache_ka(item:string(dir, "/"), port:port);
	if (isnull(res)) exit(0);

	#Powered by <a href="http://yapig.sourceforge.net" title="Yet Another PHP Image Gallery">YaPig</a> V0.92b
 	if(egrep(pattern:"Powered by .*YaPig.* V0\.([0-8][0-9][^0-9]|9([01]|2[ab]))", string:res))
 	{
 		security_hole(port);
		exit(0);
	}
 
}
