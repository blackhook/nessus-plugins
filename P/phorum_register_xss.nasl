#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(19584);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-2836");
  script_bugtraq_id(14726);

  script_name(english:"Phorum register.php Username Field XSS");

  script_set_attribute(attribute:"synopsis", value:
"A remote CGI is vulnerable to cross-site scripting.");
  script_set_attribute(attribute:"description", value:
"The remote version of Phorum contains a script called 'register.php'
which is vulnerable to a cross-site scripting attack.  An attacker may
exploit this problem to steal the authentication credentials of third
party users.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2005/Sep/22");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Phorum 5.0.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phorum:phorum");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("phorum_detect.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80, embedded:TRUE);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


install = get_kb_item(string("www/", port, "/phorum"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^([0-4]\..*|5\.0\.([0-9][^0-9]*|1[0-7][^0-9]*))$")
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
