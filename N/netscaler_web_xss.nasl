#%NASL_MIN_LEVEL 70300
# netscaler_web_xss.nasl
# GPLv2
#
# History:
#
# 1.00, 11/21/07
# - Initial release

# Changes by Tenable:
# - Revised plugin title (9/23/09)
# - Added CPE and updated copyright (10/18/2012)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29225);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2007-6037");
  script_bugtraq_id(26491);

  script_name(english:"NetScaler Web Management ws/generic_api_call.pl standalone Parameter XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to cross-site scripting attacks.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix NetScaler web management interface is susceptible to
cross-site scripting attacks.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/483920/100/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:netscaler");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (c) 2007-2022 nnposter");

  script_dependencies("netscaler_web_login.nasl");
  script_require_keys("www/netscaler");
  script_require_ports("Services/www", 80);

  exit(0);
}


if (!get_kb_item("www/netscaler")) exit(0);


include("url_func.inc");
include("http_func.inc");
include("http_keepalive.inc");


port=get_http_port(default:80, embedded:TRUE);
if (!get_tcp_port_state(port) || !get_kb_item("www/netscaler/"+port))
    exit(0);

xss="</script><script>alert(document.cookie)</script><script>";
url="/ws/generic_api_call.pl?function=statns&standalone="+urlencode(str:xss);

resp=http_keepalive_send_recv(port:port,
                              data:http_get(item:url,port:port),
                              embedded:TRUE);
if (!resp || xss>!<resp) exit(0);

report = string(
    "\n",
    "The following URLs have been found vulnerable :\n",
    "\n",
    ereg_replace(string:url,pattern:"\?.*$",replace:"")

);
security_warning(port:port, extra:report);
set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
