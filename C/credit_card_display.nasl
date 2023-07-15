#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122648);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/07");

  script_name(english:"Credit Card Disclosure in HTML");
  script_summary(english:"Checks for potential credit card information displayed on a webpage.");

  script_set_attribute(attribute:"synopsis", value:
"The web application displays plaintext credit card
information.");
  script_set_attribute(attribute:"description", value:
"The remote web application displays plaintext credit
card information without the appropriate masking.");
  script_set_attribute(attribute:"solution", value:
"Full credit card numbers should not be displayed. Partial 
credit card numbers must be appropriately masked.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Information Disclosure Score");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webmirror3.nbin");
  script_require_keys("Settings/enable_web_app_tests", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("lists.inc");


function luhn_check(num)
{
  var last, sum, i, n;
  if(len(num) != 16)
    return FALSE;

  last = num[15];
  sum = 0;
  for(i = 14; i >= 0; i--)
  {
    n = num[i];
    if(i % 2 == 0)
    {
      n *= 2;
      if(n > 9)
        n -= 9;
    }
    sum += n;
  }
  sum = ( sum * 9 ) % 10;
  return sum == last;

}

port = get_http_port(default:80);

if(report_paranoia < 2)
  audit(AUDIT_PARANOID);

report = '';

init_cookiejar();
cgis = get_kb_list('www/'+port+'/cgi');

foreach cgi (cgis)
{
  args = get_kb_list('www/'+port+'/cgi-arg'+cgi);
  if(cgi !~ "credit[_-]*card" &&
      cgi !~ "cc[_-]*(num|info|date|cvc)" &&
      max_index(collib::filter(args, f:function(){
        return _FCT_ANON_ARGS[0] =~ "credit[_-]*card" || _FCT_ANON_ARGS[0] =~ "cc[_-]*(num|info|date|cvc)";
      })) == 0)
    continue;
  res = http_send_recv3(
      port:port,
      item:cgi,
      method:"GET");
  if(empty_or_null(res))
    continue;
  m = pregmatch(pattern:"(?:[0-9]{4}[\s-.:]{0,1}){3}[0-9x\*]{4}", string:res[2]);
  if(empty_or_null(m))
    continue;
  num = [];
  for(i = 0; i < strlen(m[0]); i++)
  {
    n = ord(m[0][i]);
    if(n < 48 || n > 58)
      continue;
    collib::push(int(m[0][i]), list:num);
  }
  if(luhn_check(num:num))
    report += '  '+cgi+'\n';
}


if(strlen(report))
{
  report = 'The following URLs return credit card information :\n' + report;
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
