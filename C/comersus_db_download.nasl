#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20130);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/07");
  script_bugtraq_id(15251, 70160);

  script_name(english:"Comersus Cart /comersus/database/comersus.mdb Direct Request Datbase Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is prone to an
information disclosure attack.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Comersus Cart, an ASP shopping
cart application.

The version of Comersus Cart installed on the remote host fails to
restrict access to its customer database, which contains order
information, passwords, credit card numbers, etc. Further, the data in
all likelihood can be decrypted trivially since the application
reportedly uses the same default password for each version of the
application to encrypt and decrypt data.");
  # https://downloads.securityfocus.com/vulnerabilities/exploits/backoffice_mult_exp.pl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea058136");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/ASP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, asp: 1);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/comersus", "/store", "/shop", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  if (dir == '')	u = '/';
  else			u = dir;

  res = http_get_cache(item: u, port:port, exit_on_fail: 1);

  if (
    'href="comersus_showCart.asp' >< res ||
    'Powered by Comersus ASP Shopping Cart' >< res ||
    ':: Comersus</title>' >< res 
  )
  {
    # Try to exploit the flaw.
    r = http_send_recv3(method: 'HEAD', version: 11, port: port, item: dir + "/database/comersus.mdb", exit_on_fail: 1);

    # There's a problem if it looks like we can download the database.
    if ("Content-Type: application/x-msaccess" >< r[1])
    {
      security_warning(port);
      exit(0);
    }
  }
}
