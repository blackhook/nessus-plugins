#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104276);
  script_version("1.5");
  script_cvs_date("Date: 2018/08/08 12:52:13");


  script_name(english:"ONVIF Username and Password leak");
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
  script_set_attribute(attribute:"solution", value:
"If available, upgrade to the latest firmware. If no fix
exists for your device then, if possible, disable ONVIF.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  # https://safeandsavvy.f-secure.com/2017/06/06/foscam-ip-cameras-insecure-iot/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?701d0be3");
  # http://images.news.f-secure.com/Web/FSecure/%7B43df9e0d-20a8-404a-86d0-70dcca00b6e5%7D_vulnerabilities-in-foscam-IP-cameras_report.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc402ec0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CGI abuses");

  script_dependencie("onvif_get_stream_uri.nasl");
  script_require_keys("onvif/present", "onvif/stream");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('audit.inc');
include("data_protection.inc");

get_kb_item_or_exit('onvif/present');
port = get_kb_item_or_exit('onvif/http/port');
uris = get_kb_list_or_exit('onvif/stream/' + port);

foreach uri(uris)
{
    # http://192.168.1.178:80/iphone/11?login:password&amp;
    bad_uri = pregmatch(string:uri, pattern:'^http://[^\\?]+\\?([^:]+):(.*)&amp;$');
    if (!empty_or_null(bad_uri))
    {
      # mask the actual password
      pass = bad_uri[2];
      obfuscated = '**';
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
}

audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
