#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# From: "Frog Man" <leseulfrog@hotmail.com>
# To: bugtraq@securityfocus.com
# Cc: vulnwatch@vulnwatch.org
# Subject: [VulnWatch] Kietu ( PHP )

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11328);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(9499);

  script_name(english:"Kietu index.php Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a
remote file inclusion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Kietu web statistics application hosted on the
remote web server fails to sanitize user-supplied input to the
'url_hit' parameter of the 'index.php' script before using it to
include PHP code.  Regardless of PHP's 'register_globals' setting, an
unauthenticated attacker can exploit this issue to view arbitrary
files or possibly to execute arbitrary PHP code, possibly taken from
third-party hosts.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2003/Feb/210");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:W/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kietu:kietu");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_keys("www/PHP");
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

port = get_http_port(default:80, embedded: 0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 local_var r, w;

 w = http_send_recv3(item:string(loc, "/index.php?kietu[url_hit]=http://example.com/"),
 		method:"GET", port:port);			
 if (isnull(w)) exit(0);
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if(egrep(pattern:".*http://example.com/config\.php", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}


dirs = make_list(cgi_dirs(), "/");


foreach dir (dirs)
{
 check(loc:dir);
}
