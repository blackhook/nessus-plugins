#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103514);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/09/27 21:37:02 $");

  script_name(english:"Grandstream Phone Web Interface Default Credentials");
  script_summary(english:"Tries to login with the default credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote web interface is protected with a default password.");
  script_set_attribute(attribute:"description", value:
"The remote device appears to be a Grandstream phone which contains
a web interface with default credentials enabled.");
  script_set_attribute(attribute:"solution", value:
"Replace the default password with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("grandstream_www_detect.nbin");
  script_require_keys("installed_sw/Grandstream Phone");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

###
# Login to the web UI using the provided creds.
#
# @param username the user to login as
# @param password the password to login with
# @return TRUE on succesful login. FALSE otherwise
##
function do_login(username, password)
{
  var res = http_send_recv3(
    method:'POST',
    item:'/cgi-bin/dologin',
    data:'username=' + username + '&password=' + password,
    port:port,
    add_headers: {'Content-Type':'application/x-www-form-urlencoded'},
    exit_on_fail:FALSE);

  # The server will always respond with 200 OK. But success should also
  # include the session-role cookie getting set as well as a success
  # response.
  if ("200 OK" >!< res[0] || "Set-Cookie: session-role" >!< res[1] ||
    ('"response": "success"' >!< res[2] && '"response":"success"' >!< res[2]))
  {
    return FALSE;
  }

  return TRUE;
}

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

get_install_count(app_name:"Grandstream Phone", exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:"Grandstream Phone", port:port);

results = NULL;

if (do_login(username:"admin", password:"admin") == TRUE)
{
  results += 'admin/admin\n';
}

if (do_login(username:"user", password:"123") == TRUE)
{
  results += 'user/123\n';
}

if (empty_or_null(results)) audit(AUDIT_HOST_NOT, "affected");

report = 
  '\n' + "Nessus was able to log into the remote web interface" +
  '\n' + "using the following default credentials :" +
  '\n' +
  '\n' + results;
security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
exit(0);
