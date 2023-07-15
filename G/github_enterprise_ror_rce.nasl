#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105374);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/15 20:50:17");
  script_xref(name:"EDB-ID", value:"41616");

  script_name(english:"GitHub Enterprise Management Console RCE");
  script_summary(english:"Deserializes the cookie and checks if it returns an expected result.");

  script_set_attribute(attribute:"synopsis", value:
"GitHub Enterprise has a flaw that allows the attacker to forge cookies
 and execute arbitrary code.");

  script_set_attribute(attribute:"description", value:
"GitHub Enterprise contains a flaw in the management console that is 
due to Ruby on Rails using a static session secret, which can allow 
a remote attacker to forge cookies. These cookies are insecurely 
deserialized, potentially allowing the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?501f301f");
  script_set_attribute(attribute:"see_also", value:"https://bounty.github.com/researchers/iblue.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to GitHub Enterprise 2.8.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("github_enterprise_detect.nbin");
  script_require_ports("Services/www", 8443);
  script_require_keys("installed_sw/GitHub Enterprise");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("webapp_func.inc");
include("url_func.inc");

app = "GitHub Enterprise";
SECRET = "641dd6454584ddabfed6342cc66281fb";

get_install_count(app_name:app, exit_if_zero:TRUE);


#getting the https port for github enterprise to connect to 
port = get_http_port(default:8443);

install = get_single_install(app_name:app, port:port);

#Get the http redirect if there is
res = http_send_recv3(method:'GET', port:port, item:install['path'], exit_on_fail:TRUE);

cookie_info = pregmatch(pattern: "Set-Cookie: ([^=]+)=([^-]+)--([0-9a-fA-F]+);", string: res[1]);

if (isnull(cookie_info))
{
  audit(AUDIT_LISTEN_NOT_VULN, app, port);
}
else
{
  name = cookie_info[1];
  data = cookie_info[2];
  data = urldecode( estr:data );
  hmac = cookie_info[3];
  hmac_sha1 = tolower(bn_raw2hex(HMAC_SHA1(key:SECRET,data:data)));

  if (hmac == hmac_sha1)
  {
      security_report_v4(severity:SECURITY_HOLE, port:port, extra:"Nessus is able to forge cookies that allows to execute code on GitHub Enterprise Server");
  }
  else
  {
      audit(AUDIT_LISTEN_NOT_VULN, app, port);
  }
}

