#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104571);
  script_version("1.2");
  script_cvs_date("Date: 2018/05/16 19:05:10");

  script_xref(name:"TRA", value:"TRA-2017-33");

  script_name(english:"ONVIF Snapshot Username and Password Leak");
  script_summary(english:"Acquires the username and password from an ONVIF enabled server");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an information disclosure
vulnerability");
  script_set_attribute(attribute:"description", value:
"The remote ONVIF enabled device is affected by an information
disclosure vulnerability. An unauthenticated, remote attacker
can exploit this to disclose sensitive information related
to the device, specifically the admin username and password.");
  script_set_attribute(attribute:"see_also", value:"https://www.onvif.org/");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2017-33");
  script_set_attribute(attribute:"solution", value:
"If available, upgrade to the latest firmware. If no fix
exists for your device then, if possible, disable ONVIF.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CGI abuses");

  script_dependencie("onvif_get_snapshot.nasl");
  script_require_keys("onvif/present", "onvif/snapshot");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('audit.inc');
include("data_protection.inc");

get_kb_item_or_exit('onvif/present');
port = get_kb_item_or_exit('onvif/http/port');
uri = get_kb_item_or_exit('onvif/snapshot/' + port);

# http://192.168.1.178:80/web/auto.jpg?-usr=admin&amp;-pwd=password&amp;
bad_uri = pregmatch(string:uri, pattern:'^https?://[^\\?]+\\?-usr=(.+)&amp;-pwd=(.+)&amp;$');
if (!empty_or_null(bad_uri))
{
  # mask the actual password
  pass = bad_uri[2];
  obfuscated_password = '**';
  if (len(pass) > 2)
  {
    obfuscated_password = strcat(pass[0], crap(data:'*', length:len(pass) - 2), pass[strlen(pass)-1]);
  }

  report = 
    '\n' + "Nessus was able to determine the admin username and" +
    '\n' + "password for the remote host. Note the real password" +
    '\n' + "has been obfuscated :" +
    '\n' +
    '\n' + "  Username: " + data_protection::sanitize_user_enum(users:bad_uri[1]) +
    '\n' + "  Password: " + obfuscated_password + '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
  exit(0);
}

audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
