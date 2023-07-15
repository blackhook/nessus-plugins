#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45568);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(39474);

  script_name(english:"Iomega smbwebclient.php Unauthenticated Filesystem Access");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows
unauthenticated access to the filesystem.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be an Iomega device, perhaps a Home Media
Network Hard Drive, a Network-attached storage (NAS) device intended
for the home networks.

Its web server hosts an unsecured install of smbwebclient, a PHP-
based utility that grants full access to any visible shares on the
device itself and possibly even read or write access to shares
available on the local network to which the device is attached.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/510715/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to firmware version 2.063 or later as that reportedly
resolves the vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);


# Grab the initial page.
res = http_get_cache(item:"/", port:port, exit_on_fail: 1);

if (
  ' Remote Access Login ' >!< res &&
  !preg(pattern:"^&copy; Copyright .+ Iomega Corporation\. All rights reserved\.", string:res)
) exit(0, "The web server on port "+port+" does not look like an Iomega device.");


# Loop through directories.
if (thorough_tests) dirs = make_list(cgi_dirs());
else dirs = make_list("/cgi-bin");

script_found = FALSE;

foreach dir (dirs)
{
  # Try to exploit the issue to access a list of shares.
  url = dir + '/smbwebclient.php';

  res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
  if (
    res[2] &&
    'smbwebclient.php?O=NA" >Name</a>' >< res[2]
  )
  {
    script_found = TRUE;

    report = '\n' +
      'Nessus was able to verify the issue using the following URL :\n' +
      '\n' +
      '  ' + build_url(port:port, qs:url) + '\n';

    security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
    exit(0);
  }
}
if (!script_found) exit(0, "The iomega Home Media Network Hard Drive smbwebclient was not found on the web server on port "+port+".");
else exit(0, "The iomega Home Media Network Hard Drive smbwebclient install on port "+port+" is not affected.");
