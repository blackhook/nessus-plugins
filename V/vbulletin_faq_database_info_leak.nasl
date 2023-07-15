#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47862);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(41875);
  script_xref(name:"SECUNIA", value:"40675");

  script_name(english:"vBulletin Database Credentials Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"A bulletin board system running on the remote web server has an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of vBulletin running on the remote host has an
information disclosure vulnerability.  Requesting 'faq.php' with a
search term of 'database' results in the disclosure of the database
credentials.

An unauthenticated, remote attacker could exploit this to learn the
database credentials, which could be used to mount further attacks.");
  # https://www.vbulletin.com/forum/forum/vbulletin-3-8/vbulletin-3-8-questions-problems-and-troubleshooting/366521-mega-exploit-in-3-8-6?357801-Mega-exploit-in-3_8_6=
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4bb1d5f");
  # https://www.vbulletin.com/forum/forum/vbulletin-announcements/vbulletin-announcements_aa/366538-security-patch-release-3-8-6-pl1?357818-Security-Patch-Release-3_8_6-PL1=
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ceb82e19");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vBulletin 3.8.6-PL1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vbulletin:vbulletin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vbulletin_detect.nasl");
  script_require_keys("www/vBulletin");
  script_exclude_keys("Settings/disable_cgi_scanning");
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
install = get_install_from_kb(appname:'vBulletin', port:port, exit_on_fail:TRUE);
url = install['dir'] + '/faq.php?do=search&q=database&match=all&titlesonly=0';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if (
  '<span class="highlight">Database</span> Name:' >< res[2] &&
  '<span class="highlight">Database</span> Host:' >< res[2] &&
  '<span class="highlight">Database</span> Port:' >< res[2] &&
  '<span class="highlight">Database</span> Username:' >< res[2] &&
  '<span class="highlight">Database</span> Password:' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    trailer = NULL;

    if (report_verbosity > 1)
    {
      info = NULL;

      foreach item (make_list('Name', 'Host', 'Port', 'Username'))
      {
        pattern = '<span class="highlight">Database</span> '+item+': ([^ <]+)';
        match = eregmatch(string:res[2], pattern:pattern);
        if (match) info += '\nDatabase '+item+' : '+match[1];
      }

      if (!isnull(info))
      {
        trailer =
          'Which returned the following information :\n' +
          data_protection::sanitize_user_full_redaction(output:info) +
          '\n\nPlease note the password has been omitted from the report.\n';
      }
    }

    report = get_vuln_report(items:url, port:port, trailer:trailer);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
{
  vb_url = build_url(qs:install['dir'], port:port);
  exit(0, 'The vBulletin install at '+vb_url+' is not affected.');
}
