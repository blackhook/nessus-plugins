#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(105159);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/22");


  script_name(english:"AXIS HTTP GET Heap Overflow");
  script_summary(english:"Sends an HTTP request");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an heap overflow vulnerability
that may lead to remote code execution.");
  script_set_attribute(attribute:"description", value:
"The remote AXIS device is affected by a heap overflow vulnerability
in its web administration interface due to a flaw in handling of
special characters. An unauthenticated remote attacker can exploit
this vulnerability for denial of service and possibly remote code
execution.");
  script_set_attribute(attribute:"see_also", value:"https://www.axis.com/files/faq/Advisory_ACV-120444.pdf");
  script_set_attribute(attribute:"solution", value:
"Follow the vendor recommendation for upgrade or mitigation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Heap Overflow Vulnerability");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:axis:network_camera");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");


  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");


  script_dependencies("axis_www_detect.nbin");
  script_require_keys("installed_sw/AXIS device");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('webapp_func.inc');

get_install_count(app_name:"AXIS device", exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:"AXIS device", port:port);

# first verify the device has the correct web interface
res = http_send_recv3(method:'GET', item:'/index.shtml?size=DEADBEEF', port:port, exit_on_fail:TRUE);
if ("200 OK" >!< res[0] || empty_or_null(res[2]))
{
  audit(AUDIT_DEVICE_NOT_VULN, "The AXIS " + install["model"], install["version"]);
}

# verify deadbeef ends the variable
if (pregmatch(string:res[2], pattern:'"&size=DEADBEEF";') == NULL)
{
  audit(AUDIT_DEVICE_NOT_VULN, "The AXIS " + install["model"], install["version"]);
}

# trigger the information leak that the heap overflow is built on
res = http_send_recv3(method:'GET', item:'/index.shtml?size=DEADBEEF%', port:port);
if ("200 OK" >!< res[0] || empty_or_null(res[2]))
{
  # We should still get a response
  audit(AUDIT_RESP_BAD, 80, "an HTTP request", "HTTP");
}

# trigger information leak
match = pregmatch(string:res[2], pattern:'"&size=DEADBEEF([^"]+)";');
if (empty_or_null(match))
{
  audit(AUDIT_DEVICE_NOT_VULN, "The AXIS " + install["model"], install["version"]);
}

# look for items we know should appear in the leak
if ("http_user_agent=" >< match[1] ||
    "http_user" >< match[1] ||
    "http_remote_addr" >< match[1] ||
    "http_remote_port" >< match[1])
{
  report = '\nThe following URL can be used to trigger a heap overflow:\n' +
           '\n' + build_url(port:port, qs:'/index.shtml') + '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}

audit(AUDIT_DEVICE_NOT_VULN, "The AXIS " + install["model"], install["version"]);
