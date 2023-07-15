#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# 2002-06-07 [Michel Arboi]
# I added aexp3.htr and the comment about the locked account.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10371);
  script_version("1.43");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-1999-0407", "CVE-2002-0421");
  script_bugtraq_id(2110, 4236);

  script_name(english:"Microsoft IIS /iisadmpwd/aexp2.htr Password Policy Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a password policy bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"Microsoft IIS installs the 'aexp2.htr', 'aexp2b.htr', 'aexp3.htr', or
'aexp4.htr' files in the '/iisadmpwd' directory by default. These
fiels can be used by an attacker to brute-force a valid
username/password. A valid user may also use it to change his password
on a locked account, bypassing password policy.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Mar/113");
  script_set_attribute(attribute:"solution", value:
"Remote the HTR ISAPI filter mapping from IIS and use Microsoft Active
Directory Service Interfaces for handling accounts remotely.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2000-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");
include("global_settings.inc");
include("http.inc");
port = get_http_port(default:80);

function test_cgi(port, cgi, output)
{
 local_var res;

 res = http_send_recv3(method:"GET", item:cgi, port:port, exit_on_fail: 1);

 if (output >< res[2])
 {
   security_hole(port);
   exit(0);
 }
 return(0);
}
 
 


sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
if(get_port_state(port))
{
  test_cgi(port:port, 
 	  cgi:"/iisadmpwd/aexp.htr",
	  output:"IIS - Authentication Manager");	  

  test_cgi(port:port, 
 	  cgi:"/iisadmpwd/aexp2.htr",
	  output:"IIS - Authentication Manager");	  
  test_cgi(port:port,
          cgi:"/iisadmpwd/aexp2b.htr",
          output:"IIS - Authentication Manager"); 
  test_cgi(port:port,
          cgi:"/iisadmpwd/aexp3.htr",
          output:"IIS - Authentication Manager");      
  test_cgi(port:port,
          cgi:"/iisadmpwd/aexp4.htr",
          output:"IIS - Authentication Manager");      

  test_cgi(port:port,
          cgi:"/iisadmpwd/aexp4b.htr",
          output:"IIS - Authentication Manager");      
}
	  
