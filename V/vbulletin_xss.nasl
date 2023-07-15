#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14792);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-0620");
  script_bugtraq_id(10602, 10612);

  script_name(english:"vBulletin newreply.php WYSIWYG_HTML Parameter XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to
cross-site scripting attacks.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of vBulletin is vulnerable
to a cross-site scripting issue, due to a failure of the application
to properly sanitize user-supplied input. 

As a result of this vulnerability, it is possible for a remote
attacker to create a malicious link containing script code that will
be executed in the browser of an unsuspecting user when followed. 

This may facilitate the theft of cookie-based authentication
credentials as well as other attacks.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2004/Jun/395");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vBulletin 3.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jelsoft:vbulletin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("vbulletin_detect.nasl");
  script_require_keys("www/vBulletin");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80, embedded:TRUE);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if ( ver =~ '^3.0(\\.[01])?[^0-9]' )
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
