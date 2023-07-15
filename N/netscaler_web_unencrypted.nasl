#%NASL_MIN_LEVEL 70300
# netscaler_web_unencrypted.nasl
# GPLv2

# Changes by Tenable:
# - Revised plugin title (9/23/09)
# - Added CPE and updated copyright (10/18/2012)
# - Corrected encryption testing (1/2/2018)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29224);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"NetScaler Unencrypted Web Management Interface");

  script_set_attribute(attribute:"synopsis", value:
"The remote web management interface does not encrypt connections.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix NetScaler web management interface does use TLS or
SSL to encrypt connections.");
  script_set_attribute(attribute:"solution", value:
"Consider disabling this port completely and using only HTTPS.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:netscaler");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (c) 2007-2022 nnposter");

  script_dependencies("netscaler_web_detect.nasl");
  script_require_keys("www/netscaler");
  script_require_ports("Services/www", 80);

  exit(0);
}


if (!get_kb_item("www/netscaler")) exit(0);


include("global_settings.inc");
include("http_func.inc");


function is_ssl(port)
{
  local_var encaps, ssl_list, ssl_port;

  encaps = get_kb_item("Transports/TCP/"+port);

  if (encaps && encaps > ENCAPS_IP)
    return TRUE;
  else
  {
    ssl_list = get_kb_list("Transport/SSL");
    foreach (ssl_port in ssl_list)
    {
      if (ssl_port == port)
        return TRUE;
    }
  }

  return FALSE;
}


port=get_http_port(default:80, embedded:TRUE);
if (!get_tcp_port_state(port) || !get_kb_item("www/netscaler/"+port))
    exit(0);

if (!is_ssl(port:port)) security_warning(port);
