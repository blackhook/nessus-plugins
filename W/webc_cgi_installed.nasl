#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11515);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"AutomatedShops webc.cgi Installation Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running WebC.cgi.");
  script_set_attribute(attribute:"description", value:
"The remote host is running webc.cgi, a shopping cart application.

By default, webc.cgi sends some information to every user, including
its version number, serial number and company name. This script extracts
this information and displays it to the user.");
  script_set_attribute(attribute:"see_also", value:"http://www.automatedshops.com/");
  script_set_attribute(attribute:"solution", value:
"N/A");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:automatedshops:webc.cgi");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "no404.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 w = http_send_recv3(method:"GET", item:string(dir, "/webc.cgi/"), port:port);
 if (isnull(w)) exit(0);
 res = strcat(w[0], w[1], '\r\n', w[2]);

 data = egrep(pattern:"WEBC_", string:res);
 if(data)
 {
  report = "AutomatedShops webc.cgi is running under " + dir + "
By making a bogus request to it, we could obtain the following information :

" + data + "

This data might be potentially valuable to an attacker.

Solution : None
Risk factor : Low";

  version = egrep(pattern:"WEBC_VERSION", string:data);
  if(version)set_kb_item(name:string("www/", port, "/content/webc.cgi/version"),
  			 value:ereg_replace(pattern:"WEBC_VERSION = (.*)",
			 		    string:version - string("\n"),
					    replace:"\1"));


  security_note(port:port, extra:report);
  exit(0);
 }
}
