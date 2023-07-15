#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47833);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2010-2914");
  script_bugtraq_id(41966);
  script_xref(name:"Secunia", value:"40722");

  script_name(english:"Nessus Web Server XSS");

  script_set_attribute(attribute:"synopsis", value:
"A web server running on the remote host is affected by a cross-site
scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Nessus web server
running on the remote host is affected by a cross-site scripting
vulnerability due to improper validation of input to a GET parameter
before returning it to users. A remote attacker can exploit this, via
a specially crafted request, to execute arbitrary script code in a
user's browser session.");
  script_set_attribute(attribute:"see_also", value:"https://community.tenable.com/message/7245#7245");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2010-01");
  script_set_attribute(attribute:"solution", value:
"Upgrade the plugin feed using 'nessus-update-plugins', restart the web
server, and verify web server version 1.2.4 or later is running. The
web server version can be viewed by logging in and clicking the
'About' button.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-2914");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nessus_detect.nasl", "nessus_installed_win.nbin", "nessus_installed_linux.nbin", "macos_nessus_installed.nbin");
  script_require_keys("installed_sw/Tenable Nessus");

  exit(0);
}

include("http.inc");
include("install_func.inc");

get_install_count(app_name:"Tenable Nessus", exit_if_zero:TRUE);

var port = get_http_port(default:8834);

var install = get_single_install(app_name:"Tenable Nessus", port:port, exit_if_unknown_ver:TRUE);
var path = install['path'];
var install_loc = build_url(port:port, qs:path);

var version = install['version'];
var web_ui_version = install['Web server version'];
if (empty_or_null(web_ui_version)) web_ui_version = install['version'];
if (empty_or_null(web_ui_version)) web_ui_version = UNKNOWN_VER;

if (web_ui_version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER, "Nessus web UI");

if (ver_compare(ver:web_ui_version, fix:'1.2.4') == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    var report = '\n  Installed web UI version : ' + web_ui_version +
             '\n  Fixed web UI version     : 1.2.4\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Nessus", install_loc, version + " with web UI " + web_ui_version);
