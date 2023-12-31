#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17972);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-1006");
  script_bugtraq_id(12984);

  script_name(english:"SonicWALL SOHO Web Interface XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple cross-site scripting
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is a SonicWALL SOHO appliance.

This version is affected by multiple issues, specifically a cross-
site scripting vulnerability due to a lack of sanitization of
user-supplied data.

Successful exploitation of this issue may allow an attacker to execute 
malicious script code on a vulnerable appliance.");
  script_set_attribute(attribute:"see_also", value:"https://www.sonicwall.com/en-us/home");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:sonicwall:soho");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

#the code

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80, embedded:TRUE);
if ( ! get_port_state(port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1, embedded:TRUE);
if( r == NULL )exit(0);

#if(egrep(pattern:"<title>SonicWall</title>.*<script>foo</script>", string:r))
if(egrep(pattern:"SonicWall", string:r, icase:TRUE) &&
   egrep(pattern:"<script>foo</script>", string:r))
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
