#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53575);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(47398);
  script_xref(name:"SECUNIA", value:"44194");
  script_xref(name:"SECUNIA", value:"44204");

  script_name(english:"Atlassian Confluence 2.x >= 2.7 / 3.x < 3.4.6 Multiple XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by multiple cross-site
scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of
Atlassian Confluence on the remote host is a 2.x version that is 2.7
or later, or else version 3.x prior to 3.4.6. It is, therefore,
affected by multiple, cross-site scripting vulnerabilities.

Errors in the validation of input data to certain macros allow
unfiltered data to be returned to a user's browser. The affected
macros are: Code, Attachments, Bookmarks, Global Reports, Recently
Updated, Pagetree, Create Space Button and Documentation Link.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://confluence.atlassian.com/doc/confluence-security-advisory-2011-01-18-225117982.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1c4240b");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONF-21098");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONF-21099");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONF-21390");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONF-21391");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONF-21392");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONF-21393");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONF-21394");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONF-21508");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Confluence version 3.4.6 or later, or apply the appropriate
vendor patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

  script_dependencies("confluence_detect.nasl");
  script_require_keys("www/confluence", "Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8080);

install = get_install_from_kb(
  appname      :'confluence',
  port         :port,
  exit_on_fail :TRUE
);

dir     = install['dir'];
version = install['ver'];
install_url = build_url(port:port, qs:dir);

if (isnull(version) || version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Confluence", install_url);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ '^3(\\.4)?$')
{
  gran = FALSE;
  # Check build (if we have it) to see if we do indeed have version 3.4
  # or if our version is not granular enough. Build info can be found at
  # https://developer.atlassian.com/display/CONFDEV/Confluence+Build+Information
  build = get_kb_item("www/" +port+ "/confluence/build/" + dir);

  if (build != UNKNOWN_VER)
  {
    if (build == "2029") gran = TRUE;
  }
  if (!gran)
    audit(AUDIT_VER_NOT_GRANULAR, "Confluence", port, version);
}

ver = split(version,sep:'.', keep:FALSE);
  for (x=0; x<max_index(ver); x++)
    ver[x] = int(ver[x]);

# Affects:
# 2.7 - 3.4.5
if (
  (ver[0] == 2 && ver[1] >= 7) ||
  (
    ver[0] == 3 &&
    (
      ver[1] < 4 ||
      (ver[1] == 4 && ver[2] < 6)
    )
  )
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.4.6' +
      '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Confluence", install_url, version);
