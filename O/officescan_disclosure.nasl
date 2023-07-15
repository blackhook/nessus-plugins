#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID

# References :
# Date:  Tue, 16 Oct 2001 11:34:56 +0900
# From: "snsadv@lac.co.jp" <snsadv@lac.co.jp>
# To: bugtraq@securityfocus.com
# Subject: [SNS Advisory No.44] Trend Micro OfficeScan Corporate Edition
# (Virus Buster Corporate Edition) Configuration File Disclosure Vulnerability
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
 script_id(11074);
 script_version("1.25");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

 script_cve_id("CVE-2001-1151");
 script_bugtraq_id(3438);

 script_name(english:"Trend Micro OfficeScan ofcscan.ini Configuration File Disclosure");
 script_summary(english:"Checks for the presence of /officescan/hotdownload/ofscan.ini");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by an information
disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote Trend Micro OfficeScan Corporate Edition (Japanese version:
Virus Buster Corporate Edition) web-based management console allows
unauthenticated access to files under '/officescan/hotdownload'.

Reading the configuration file 'ofcscan.ini' under that location will
reveal information about the target. For example, it contains
passwords that are encrypted using a weak algorithm.");
 # https://web.archive.org/web/20011223111241/http://www.lac.co.jp/security/english/snsadv_e/44_e.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8bdd721");
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2001/Oct/102");
 script_set_attribute(attribute:"solution", value:"Contact the vendor for a fix.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2001-1151");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/10/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/14");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2002-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("data_protection.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

dir = '/officescan/hotdownload';
file = 'ofscan.ini';
url = dir + '/' + file;

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(hdrs['$code'])) code = 0;
else code = hdrs['$code'];

req = http_last_sent_request();

if (code == 200)
{
  res2 = http_send_recv3(method:"GET", item:dir+'/nessus.ini', port:port, exit_on_fail:TRUE);
  hdrs2 = parse_http_headers(status_line:res2[0], headers:res2[1]);
  if (isnull(hdrs2['$code'])) code2 = 0;
  else code2 = hdrs2['$code'];

  if (code2 == 200 || strlen(res2[2])) exit(0, "The web server listening on port "+port+" responded to a request for 'nessus.ini'.");

  report = NULL;
  attach_file = NULL;
  output = NULL;
  request = NULL;

  if (report_verbosity > 0)
  {
    report =
      '\n' + "Nessus was able to obtain the contents of '" + file + "' with the" +
      '\n' + 'following request :' +
      '\n' +
      '\n  ' + req +
      '\n';

    if (report_verbosity > 1)
    {
      output = data_protection::sanitize_user_full_redaction(output:res[2]);
      attach_file = file;
      request = make_list(req);
    }
  }

  security_report_v4(port:port,
                     extra:report,
                     severity:SECURITY_WARNING,
                     request:request,
                     file:attach_file,
                     output:output);

  exit(0);
}
else exit(0, "The web server listening on port "+port+" is not affected.");
