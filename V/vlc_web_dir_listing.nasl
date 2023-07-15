#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(69017);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-3564");
  script_bugtraq_id(60705);

  script_name(english:"VLC Web Interface XML Services Remote Command Execution");
  script_summary(english:"Tries to send 'dir' command via web interface");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The web interface for VLC media player listening on the remote host
does not require authentication, which allows an unauthenticated remote
attacker to issue XML service commands via the VLC Web Interface.");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/vlc/releases/2.0.7.html");
  script_set_attribute(attribute:"see_also", value:"https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2013-007/?fid=3876&dl=1");
  # http://blog.spiderlabs.com/2013/06/twsl2013-006-cross-site-scripting-vulnerability-in-coldbox.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f33883d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC 2.x if necessary and configure access control lists
(ACLs) in the application to limit access to trusted hosts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vlc_web_detect.nasl");
  script_require_keys("www/VLC/installed");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8080);
appname = "VLC media player";

installed = get_kb_item("www/VLC/installed");
if (isnull(installed)) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

install_url = build_url(port:port, qs:"/");
acl = get_kb_item("www/VLC/" + port + "/acl");
if(acl) audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);
exploit = "/requests/browse.xml?dir=/";
res = http_send_recv3(
    method       : "GET",
    item         : exploit,
    port         : port
);
res = res[2];

if(
   '<?xml version="1.0"' >< res &&
   '<element' >< res &&
   '<root>' >< res &&
   'modification_time' >< res
)
{
  line_limit = 10;
  if (report_verbosity > 0)
  {
    header =
      'Nessus was able to exploit the issue using the following URL';
    trailer = '';

    if (report_verbosity > 1)
    {
      trailer =
        'Here are its contents (limited to ' + line_limit + ' lines) :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        beginning_of_response(resp:res, max_lines:line_limit) +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);
    }
    report = get_vuln_report(items:exploit, port:port, header:header, trailer:trailer);
    security_warning(port:port, extra:data_protection::sanitize_user_paths(report_text:report));
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);

