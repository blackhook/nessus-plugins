#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(49705);
 script_version("1.7");
 script_cvs_date("Date: 2018/05/24 13:59:31");

 script_name(english:"Web Server Harvested Email Addresses");
 script_summary(english:"Display email addresses");

 script_set_attribute(attribute:"synopsis", value:
"Email addresses were harvested from the web server." );
 script_set_attribute(attribute:"description", value:
"Nessus harvested HREF mailto: links and extracted email addresses by
crawling the remote web server." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/04");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Web Servers");
 script_dependencies("webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("data_protection.inc");

port = get_http_port(default: 80, embedded: 1);

l = get_kb_list("www/"+port+"/mailto");
if (isnull(l))
  exit(0, "No email addresses were gathered on port "+port+".");

n = 0;
e = '';
foreach a (l)
{
  n ++;
  e += '\n- \'' + a + '\', referenced from :\n';
  h = get_kb_list("www/"+port+"/mailto/"+a+"/*");
  if (! isnull(h))
  {
    foreach url (make_list(h))
      e += '   ' + url + '\n';
  }
}

if (n > 1) s += 'es have'; else s += ' has';
e =  '\n\nThe following email address'+s+' been gathered :\n\n' + data_protection::sanitize_email_address_multiple(text:e);
security_note(port: port, extra: e);
