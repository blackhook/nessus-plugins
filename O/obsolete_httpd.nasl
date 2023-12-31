#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(34460);
  script_version("1.51");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/10");

  script_xref(name:"IAVA", value:"0001-A-0617");

  script_name(english:"Unsupported Web Server Detection");
  script_summary(english:"Checks for old HTTPD banners.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is obsolete / unsupported.");
  script_set_attribute(attribute:"description", value:
"According to its version, the remote web server is obsolete and no
longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it may contain security
vulnerabilities.");
  script_set_attribute(attribute:"solution", value:
"Remove the web server if it is no longer needed. Otherwise, upgrade to a
supported version if possible or switch to another server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Web Servers");

  script_dependencies("http_version.nasl", "peercast_installed.nasl", "www_fingerprinting_hmap.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include('http.inc');

var port = get_http_port(default:80);

# nb: these are the possible items to report in the plugin output;
#     they need to agree with the indices in the 'data' array in
#     'check()'.
var fields = make_list(
  'Product',
  'Server response header',
  'Installed version',
  'Support ended',
  'Extended support ended',
  'Migrate to',
  'Supported versions',
  'Additional information'
);

function check(ver, dates_re, dates, dates_ext, latest, migrate, url, name)
{
  local_var data, k, l, max_llen, r, eol_date, note;

  data = make_array();

  if (!isnull(dates_re))
    foreach k (keys(dates_re))
      if (preg(string: ver, pattern: k))
      {
        if (!isnull(name))
        {
          if (typeof(name) == 'array') data['Product'] = name[k];
          else data['Product'] = name;
        }
        data['Server response header'] = ver;
        if (dates_re[k]) data['Support ended'] = dates_re[k];
        break;
      }
  if (!data['Server response header'] && ! isnull(dates))
    foreach k (keys(dates))
      if (k >< ver)
      {
        if (!isnull(name))
        {
          if (typeof(name) == 'array') data['Product'] = name[k];
          else data['Product'] = name;
        }
        data['Server response header'] = ver;
        if (dates[k]) data['Support ended'] = dates[k];
        break;
      }
  if (!data['Server response header']) return;

  if (dates_ext[k] != "")
  {
    # ignore extended support dates when report paranoia is set to 'Paranoid'
    if (report_paranoia < 2)
      checkDate(eol_date:dates_ext[k], name:data['Product']);
    else
      note =
        "Note that Nessus has not checked if "+data['Product']+" is on extended support.";

    data['Extended support ended'] = dates_ext[k];
  }
  if (latest) data['Supported versions'] = latest;
  if (migrate) data['Migrate to'] = migrate;
  if (!isnull(url))
  {
    if (typeof(url) == 'array') data['Additional information'] = url[k];
    else data['Additional information'] = url;
  }

  # nb: we are using the version rather than Server response header
  #     for Tomcat and WAS.
  if (
    data['Product'] &&
    ("Tomcat" >< data['Product'] || "WebSphere Application Server" >< data['Product'])
  )
  {
    data['Installed version'] = data['Server response header'];
    data['Server response header'] = NULL;
  }

  max_llen = 0;
  foreach l (keys(data))
    if (strlen(l) > max_llen) max_llen = strlen(l);

  # Generate report.
  r = '\n';
  foreach l (fields)
  {
    if (data[l])
    {
      if ('\n' >< data[l])
        data[l] = str_replace(find:'\n', replace:'\n'+crap(data:" ", length:2+max_llen+3), string:data[l]);
      r += '  ' + l + crap(data:" ", length:max_llen-strlen(l)) + ' : ' + data[l] + '\n';
    }

    if (!isnull(note))
      r += '\n' + note;
  }

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:r);

  exit(0);
}

# Compares specified date with current date
function checkDate(eol_date, name)
{
  local_var eol_date_arr, eol_date_unix, now;

  now = unixtime();

  if (!isnull(eol_date))
  {
    eol_date_arr  = split(eol_date, sep:'-', keep:FALSE);
    eol_date_unix = mktime(
      year: int(eol_date_arr[0]),
      mon:  int(eol_date_arr[1]),
      mday: int(eol_date_arr[2])
    );

    # Check if the specified date is after current date
    if (eol_date_unix > now)
    {
      set_kb_item(name:"www/extended_support", value:TRUE);
      set_kb_item(
        name:"www/"+port+"/extended_support",
        value:name + " support ends on " + eol_date
      );
      exit(0, name + " is on extended support.");
    }
  }
}

######################################################################
# Domino removed in favor of new SEoL plugins
######################################################################
# WebSphere Application Server removed in favor of new SEoL plugins
######################################################################
var banner = get_http_banner(port: port, exit_on_fail:TRUE);

var ver = egrep(string:banner, pattern:"^Server:", icase:TRUE);
if (!ver) exit(0, "The banner from the web server on port "+port+" doesn't have a Server response header.");
ver = ereg_replace(string:chomp(ver), pattern:"^Server: *", replace:"", icase:TRUE);

######################################################################
# Apache JServ
# nb: there's no official statement from the project, but no updates since 2001
# suggests the project's dead.
# http://en.wikipedia.org/wiki/Apache_JServ_Protocol
# http://archive.apache.org/dist/java/jserv/

if (ver =~ "(Apache|Mod_)JServ/")
{
  check(
    name  : 'Apache JServ',
    ver   : ver,
    dates_re : make_array("(Apache|Mod_)JServ/", ""),
    migrate  : "Apache Tomcat or an alternate servlet container"
  );

  # should not be reached.
  exit(1, "Nessus failed to flag the web server on port "+port+" as unsupported based on its Server response header ('"+ver+"').");
}

######################################################################
# Apache removed in favor of new SEoL plugins
######################################################################
# CERN httpd
if (ver =~ "^(CERN httpd |CERN/)")
{
  n = make_array(
    "^(CERN httpd |CERN/)3",   "CERN httpd 3.x",
    "^(CERN httpd |CERN/)2",   "CERN httpd 2.x",
    "^(CERN httpd |CERN/)0",   "CERN httpd 0.x"
  );
  v = make_array(
    "^(CERN httpd |CERN/)3",   "1996-07-15",
    "^(CERN httpd |CERN/)2",   "1994-05-05",
    "^(CERN httpd |CERN/)0",   "1993-04-28"
  );
  check(
    name     : n,
    ver      : ver,
    dates_re : v,
    url      : 'http://www.w3.org/Daemon/Status.html\nhttp://www.w3.org/Daemon/Activity.html'
  );

  # Do not add this pattern to the previous array as hashes are not sorted
  check(
    name     : 'CERN httpd',
    ver      : ver,
    dates_re : make_array("^(CERN httpd |CERN/)", "1996-07-15"),
    url      : 'http://www.w3.org/Daemon/Status.html\nhttp://www.w3.org/Daemon/Activity.html'
  );

  # should not be reached.
  exit(1, "Nessus failed to flag the web server on port "+port+" as unsupported based on its Server response header ('"+ver+"').");
}


######################################################################
# iPlanet and related servers
# This is now Glassfish
if (
  "iPlanet" >< ver ||
  "Netscape" >< ver ||
  "Sun-Java-System-Web-Server/" >< ver ||
  "Sun Java System Web Server/" >< ver ||
  "Sun-ONE-Web-Server/" >< ver ||                          # eg, "Server: Sun-ONE-Web-Server/6.1
  "SunONE WebServer " >< ver ||                            # eg, "Server: SunONE WebServer 6.0"
  "SunONE WebServer/" >< ver                               # eg, "Server: SunONE WebServer/6.0"
)
{
  n = make_array(
    "iPlanet-WebServer-Enterprise/4\.0", "iPlanet Web Server 4.0",
    "iPlanet-WebServer-Enterprise/4\.1", "iPlanet Web Server 4.1",
    "Netscape-Enterprise/3\.6",          "Netscape Enterprise Server 3.6",
    "Netscape-Enterprise/4\.0",          "Netscape Enterprise Server 4.0",
    "Sun-Java-System-Web-Server/6\.0",   "Sun Java System Web Server 6.0",
    "(Sun-ONE-Web-Server/|SunONE WebServer[ /])([0-5]\.|6\.0)", "Sun ONE Web Server"
  );
  v = make_array(
    "iPlanet-WebServer-Enterprise/4\.0", "2002-12-31",
    "iPlanet-WebServer-Enterprise/4\.1", "2004-03-31",
    "Netscape-Enterprise/3\.6",          "2001-01-01 (or earlier)",
    "Netscape-Enterprise/4\.0",          "2002-12-31",
    "Sun-Java-System-Web-Server/6\.0",   "",
    "(Sun-ONE-Web-Server/|SunONE WebServer[ /])([0-5]\.|6\.0)", ""
  );
  check(
    name     : n,
    ver      : ver,
    dates_re : v,
    migrate  : "Oracle iPlanet Web Server 7.0 / 6.1",
    url      : "http://www.oracle.com/us/support/library/lifetime-support-middleware-069163.pdf"
  );

  # These servers are very old
  # nb: what about iPlanet-Enterprise, Netsite-Commerce, Netsite-Communications?
  n = make_array(
    "Netscape-Commerce/[0-4]\.",            "Netscape Commerce Server",
    "Netscape-Communications/[0-4]\.",      "Netscape Communications Server",
    "Netscape-Enterprise/[0-4]\.",          "Netscape Enterprise Server",
    "Netscape-Fasttrack/[0-4]\.",           "Netscape FastTrack Server",
    "iPlanet-WebServer-Enterprise/[0-4]\.", "iPlanet Web Server"
  );
  v = make_array(
    "Netscape-Commerce/[0-4]\.",            "",
    "Netscape-Communications/[0-4]\.",      "",
    "Netscape-Enterprise/[0-4]\.",          "",
    "Netscape-Fasttrack/[0-4]\.",           "",
    "iPlanet-WebServer-Enterprise/[0-4]\.", ""
  );
  check(
    name     : n,
    ver      : ver,
    dates_re : v,
    migrate  : "Oracle iPlanet Web Server 7.0 / 6.1",
    url      : "http://www.oracle.com/us/support/library/lifetime-support-middleware-069163.pdf"
  );

  # nb: just drop through as the support status of things like the
  #     open source version of Netscape Communications is uncertain.
}

######################################################################
# KNet Web Server
#
# nb: there's no official statement from the project, but
#     the distribution site
#     (http://www.btinternet.com/~douglas.marsh/KNet.exe)
#     has gone MIA, and the software doesn't seem to have
#     been updated since 2005.
if (ver =~ "^KNet vv")
{
  check(
    name  : 'KNet Web Server',
    ver   : ver,
    dates : make_array("KNet vv", "")
  );

  # should not be reached.
  exit(1, "Nessus failed to flag the web server on port "+port+" as unsupported based on its Server response header ('"+ver+"').");
}

######################################################################
# Light HTTPD
#
# nb: there's no official statement from the project, but no updates since 2001 suggests the project's dead.
if (ver =~ "^Light HTTPd v")
{
  check(
    name  : 'Light HTTPD',
    ver   : ver,
    dates : make_array("Light HTTPd v", "")
  );

  # should not be reached.
  exit(1, "Nessus failed to flag the web server on port "+port+" as unsupported based on its Server response header ('"+ver+"').");
}

######################################################################
# Microsoft IIS
if (ver =~ "^Microsoft-IIS/")
{
  n = make_array(
    "Microsoft-IIS/1.0",      "Microsoft IIS 1.0",
    "Microsoft-IIS/2.0",      "Microsoft IIS 2.0",
    "Microsoft-IIS/3.0",      "Microsoft IIS 3.0",
    "Microsoft-IIS/4.0",      "Microsoft IIS 4.0",
    "Microsoft-IIS/5.0",      "Microsoft IIS 5.0",
    "Microsoft-IIS/5.1",      "Microsoft IIS 5.1",
    "Microsoft-IIS/6.0",      "Microsoft IIS 6.0",
    "Microsoft-IIS/7.0",      "Microsoft IIS 7.0",
    "Microsoft-IIS/7.5",      "Microsoft IIS 7.5"
  );
  v = make_array(
    "Microsoft-IIS/1.0",      "",
    "Microsoft-IIS/2.0",      "1997-06-30",
    "Microsoft-IIS/3.0",      "2000-03-31",
    "Microsoft-IIS/4.0",      "2004-12-31",
    "Microsoft-IIS/5.0",      "2010-07-13",
    "Microsoft-IIS/5.1",      "2014-04-08",
    "Microsoft-IIS/6.0",      "2015-07-14",
    "Microsoft-IIS/7.0",      "2020-01-14",
    "Microsoft-IIS/7.5",      "2020-01-14"
  );
  u = make_array(
    "Microsoft-IIS/1.0",      "http://support.microsoft.com/gp/lifeselectindex#I",
    "Microsoft-IIS/2.0",      "http://support.microsoft.com/lifecycle/?p1=2092",
    "Microsoft-IIS/3.0",      "http://support.microsoft.com/lifecycle/?p1=2093",
    "Microsoft-IIS/4.0",      "http://support.microsoft.com/lifecycle/?p1=2094",
    "Microsoft-IIS/5.0",      "http://support.microsoft.com/lifecycle/?p1=2095",
    "Microsoft-IIS/5.1",      "http://support.microsoft.com/lifecycle/?p1=2096",
    "Microsoft-IIS/6.0",      "http://www.nessus.org/u?d8353958", # https://docs.microsoft.com/en-us/lifecycle/products/internet-information-services-iis
    "Microsoft-IIS/7.0",      "http://www.nessus.org/u?d8353958", # https://docs.microsoft.com/en-us/lifecycle/products/internet-information-services-iis
    "Microsoft-IIS/7.5",      "http://www.nessus.org/u?d8353958" # https://docs.microsoft.com/en-us/lifecycle/products/internet-information-services-iis
  );

  check(
    name   : n,
    ver    : ver,
    dates  : v,
    latest : "Microsoft IIS 8.5 / 8.0",
    url    : u
  );

  # nb: if we get here, we know it's IIS and supported so we're done.
  exit(0, "The web server on port "+port+" is still supported based on its Server response header ('"+ver+"').");
}

######################################################################
# NCSA HTTPd
if (ver =~ "^NCSA/[1-9]")
{
  check(
    name     : 'NCSA HTTPd',
    ver      : ver,
    dates_re : make_array("^NCSA/[1-9]", "1998"),
    migrate  : 'Apache',
    url      : 'http://en.wikipedia.org/wiki/NCSA_HTTPd'
  );

  # should not be reached.
  exit(1, "Nessus failed to flag the web server on port "+port+" as unsupported based on its Server response header ('"+ver+"').");
}

######################################################################
# PeerCast
#
# nb: there's no official statement, but the website was abandoned in December 2007 and no longer works.
var peercast_version = get_kb_item("PeerCast/"+port+"/version");
if (!isnull(peercast_version))
{
  check(
    name  : 'PeerCast',
    ver   : peercast_version,
    dates : make_array("PeerCast", "")
  );

  # should not be reached.
  exit(1, "Nessus failed to flag the web server on port "+port+" as unsupported based on its version ('"+peercast_version+"').");
}

######################################################################
# SAMBAR
if (ver =~ "^SAMBAR")
{
  check(
    name     : 'Sambar Server',
    ver      : ver,
    dates_re : make_array("^SAMBAR", "2007-12-31"),
    migrate  : 'Apache',
    url      : "http://www.sambarserver.info/viewtopic.php?t=882"
  );

  # should not be reached.
  exit(1, "Nessus failed to flag the web server on port "+port+" as unsupported based on its Server response header ('"+ver+"').");
}

######################################################################
# Sami HTTP Server
if ("Sami HTTP Server" >< ver)
{
  check(
    name  : 'Sami HTTP Server',
    ver   : ver,
    dates : make_array("Sami HTTP Server", ""),
    url   : "http://www.karjasoft.com/old.php"
  );

  # should not be reached.
  exit(1, "Nessus failed to flag the web server on port "+port+" as unsupported based on its Server response header ('"+ver+"').");
}

######################################################################
# Savant Web Server
#
# nb: there's no official statement from the project, but no updates since at least 2004 suggests the project's dead.
if (ver =~ "^Savant/")
{
  check(
    name  : 'Savant Web Server',
    ver   : ver,
    dates : make_array("Savant/", ""),
    url   : "http://savant.sourceforge.net/news.html"
  );

  # should not be reached.
  exit(1, "Nessus failed to flag the web server on port "+port+" as unsupported based on its Server response header ('"+ver+"').");
}

######################################################################
if ('Oracle-Application-Server' >< ver)
{
  n = make_array(
    '^Oracle-Application-Server-9i/9\\.0\\.2', 'Oracle Application Server 9.0.2.x',
    '^Oracle-Application-Server-9i/9\\.0\\.3', 'Oracle Application Server 9.0.3.x',
    '^Oracle-Application-Server-10g/9\\.0\\.4', 'Oracle Application Server 9.0.4.x',
    '^Oracle-Application-Server-10g/10\\.1\\.2', 'Oracle Application Server 10.1.2.x'
  );

  v = make_array(
    '^Oracle-Application-Server-9i/9\\.0\\.2', '2005-07-01',
    '^Oracle-Application-Server-9i/9\\.0\\.3', '2005-07-01',
    '^Oracle-Application-Server-10g/9\\.0\\.4', '2006-12-01',
    '^Oracle-Application-Server-10g/10\\.1\\.2', '2011-12-01'
  );
  u = make_array(
    '^Oracle-Application-Server-9i/9\\.0\\.2', 'http://www.nessus.org/u?4a0600d0',
    '^Oracle-Application-Server-9i/9\\.0\\.3', 'http://www.nessus.org/u?4a0600d0',
    '^Oracle-Application-Server-10g/9\\.0\\.4', 'http://www.nessus.org/u?4a0600d0',
    '^Oracle-Application-Server-10g/10\\.1\\.2', 'http://www.nessus.org/u?4a0600d0'
  );

  check(
    name     : n,
    ver      : ver,
    dates_re : v,
    latest   : 'Oracle Application Server 10.1.3.x / 11.1.1.x',
    url      : u
  );

  exit(0, 'The web server on port '+port+' is still supported based on its Server response header (\''+ver+'\').');
}

######################################################################
# JBoss AS (Application Server)

var x_header = egrep(pattern:"JBoss", string:banner);

if(x_header)
{
  match = NULL;
  if ("JBossAS" >< x_header)
  {
    match = pregmatch(pattern:"Servlet(\s|\/)[0-9.]+; (((JBossAS-[0-9.]+)))", string:x_header);
  }
  else
  {
    match = pregmatch(pattern:"Servlet(\s|\/)[0-9.]+; ((JBoss|Tomcat)?-[0-9.]+/)?(JBoss-[^\/\s\)]+)", string:x_header);
  }
  if (!isnull(match))
  {
    ver = match[4];

    n = make_array(
      "JBoss-3\.2($|\.)",          "JBoss AS 3.2.x",
      "JBoss-4\.0($|\.)",          "JBoss AS 4.0.x",
      "JBoss-4\.2($|\.)",          "JBoss AS 4.2.x",
      "JBoss-4\.3($|\.)",          "JBoss AS 4.3.x"
    );
    # Regular support end dates
    v = make_array(
      "JBoss-3\.2($|\.)",          "",
      "JBoss-4\.0($|\.)",          "2009-09-01",
      "JBoss-4\.2($|\.)",          "2010-06-01 (end of production phase) / 2012-07-01 (end of maintenance support)",
      "JBoss-4\.3($|\.)",          "2011-01-01 (end of production phase) / 2013-01-01 (end of maintenance support)"
    );
    # Extended support end dates
    x = make_array(
      "JBoss-3\.2($|\.)",          "",
      "JBoss-4\.0($|\.)",          "",
      "JBoss-4\.2($|\.)",          "2015-06-01",
      "JBoss-4\.3($|\.)",          "2016-06-01"
    );
    u = make_array(
      "JBoss-3\.2($|\.)",          "https://access.redhat.com/site/pages/486023",
      "JBoss-4\.0($|\.)",          "https://access.redhat.com/site/support/policy/updates/jboss_notes/",
      "JBoss-4\.2($|\.)",          "https://access.redhat.com/site/support/policy/updates/jboss_notes/",
      "JBoss-4\.3($|\.)",          "https://access.redhat.com/site/support/policy/updates/jboss_notes/"
    );

    check(
      name     : n,
      ver      : ver,
      dates_re : v,
      dates_ext: x,
      latest   : "JBoss 5.x / 6.x / 7.x / Wildfly (8.x)",
      url      : u
    );

    exit(0, 'The web server on port '+port+' is still supported based on its Server response header (\''+chomp(x_header)+'\').');
  }
}

######################################################################
# Tomcat removed in favor of new SEoL plugins
######################################################################
exit(0, "Nessus does not know about the support status of the web server on port "+port+" based on its Server response header ('"+ver+"').");
