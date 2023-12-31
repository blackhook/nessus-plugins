#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
  script_id(17193);
  script_version("1.18");

  script_cve_id("CVE-2005-0493");
  script_bugtraq_id(12620);
  
  script_name(english:"BizMail bizmail.cgi Arbitrary Mail Relay");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows unauthorized
mail relaying." );
 script_set_attribute(attribute:"description", value:
"The remote web server is hosting the CGI bizmail.cgi, a CGI script for
sending the content of web forms to email addresses. 

The remote version of this software fails to sanitize the 'email'
parameter to the 'bizmail.cgi' script of CRLF sequences.  An
unauthenticated, remote attacker may be able to leverage this issue to
send spam or other sorts of abusive mail through the affected host." );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2005/Feb/362" );
 script_set_attribute(attribute:"see_also", value:"https://secuniaresearch.flexerasoftware.com/advisories/14351/" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks the version of bizmail.cgi");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
 r = http_send_recv3(method:"GET", item: dir + "/bizmail.cgi", port:port);
 res = strcat(r[0], r[1], '\r\n', r[2]);
 if ( "Biz Mail Form " >< res )
 {
  if ( egrep(pattern:"Biz Mail Form.* ([01]\.|2\.[02] )", string:res) )
	{
	security_warning( port);
	exit(0);
	}
 }
}
