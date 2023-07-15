#%NASL_MIN_LEVEL 70300
# netscaler_web_cookie_info.nasl
# GPLv2
#
# History:
#
# 1.00, 11/21/07
# - Initial release

# Changes by Tenable:
# - Revised plugin title, changed family (9/2/09)
# - changed family again (9/23/09)
# - Added CPE and updated copyright (10/18/2012)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29221);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2007-6193");

  script_name(english:"NetScaler Web Management Interface IP Address Cookie Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to an information disclosure attack.");
  script_set_attribute(attribute:"description", value:
"It is possible to extract information about the remote Citrix
NetScaler appliance obtained from the web management interface's
session cookie, including the appliance's main IP address and software
version.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/484182/100/0/threaded");
  script_set_attribute(attribute:"solution", value:
"None");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:netscaler");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (c) 2007-2022 nnposter");

  script_dependencies("netscaler_web_login.nasl");
  script_require_keys("www/netscaler", "http/password");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("misc_func.inc");
include("url_func.inc");
include("http_func.inc");

get_kb_item_or_exit("www/netscaler");
get_kb_item_or_exit("http/password");


function cookie_extract (cookie,parm)
{
local_var match;
match=eregmatch(string:cookie,pattern:' '+parm+'=([^; \r\n]*)',icase:TRUE);
if (isnull(match)) return NULL;
return match[1];
}


port=get_http_port(default:80, embedded:TRUE);
get_kb_item_or_exit("www/netscaler/"+port);
cookie = get_kb_item_or_exit("/tmp/http/auth/"+port);

found="";

nsip=cookie_extract(cookie:cookie,parm:"domain");
if (nsip && nsip+"."=~"^([0-9]{1,3}\.){4}$")
    found+='Main IP address  : '+nsip+'\n';

nsversion=urldecode(estr:cookie_extract(cookie:cookie,parm:"nsversion"));
if (nsversion)
    {
    replace_kb_item(name:"www/netscaler/"+port+"/version",
                           value:nsversion);
    found+='Software version : '+nsversion+'\n';
    }

if (!found)
 exit(0, "Netscaler version could not be extracted on port "+port+".");

report = string(
    "\n",
    "It was possible to determine the following information about the\n",
    "Citrix NetScaler appliance by examining the web management cookie :\n",
    "\n",
    found
);
security_warning(port:port,extra:report);
