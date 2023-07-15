#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77746);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-5334");
  script_bugtraq_id(69249);

  script_name(english:"FreeNAS WebGUI Blank Password");
  script_summary(english:"Checks if a password has not been set on the FreeNAS WebGUI.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has a blank password set that
allows for arbitrary command execution.");
  script_set_attribute(attribute:"description", value:
"The version of FreeNAS installed on the remote host either has not yet
set up a password or has recently reset the WebGUI password. This
allows anyone to log into the WebGUI, set up an arbitrary password,
and then use the system terminal feature of the WebGUI to execute
arbitrary commands with administrative privileges.");
  script_set_attribute(attribute:"see_also", value:"https://redmine.ixsystems.com/issues/5844");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2014/q3/389");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of FreeNAS newer than 9.2.1.7 or set a WebGUI
password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-5334");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freenas:freenas");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("freenas_web_detect.nasl");
  script_require_keys("installed_sw/FreeNAS");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "FreeNAS";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:app_name, port:port);

url = install['dir'] + '/account/login/?next=/';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if ('New Password:' >< res[2])
{
  if (report_verbosity > 0)
  {
    report = 
      '\n' + 'Nessus was able to detect a FreeNAS WebGUI without a password set.' +
      '\n' +
      '\n' + '  URL     : ' + build_url(port:port, qs:url) + 
      '\n' + '  Version : ' + install['version'] + 
      '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, build_url(port:port, qs:install['dir']));
