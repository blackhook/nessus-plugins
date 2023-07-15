#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134677);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-10189");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0026");

  script_name(english:"ManageEngine Desktop Central 10 < Build 100479 Remote Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java-based web application that is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The ManageEngine Desktop Central application running on the remote
host is version 10 prior to build 100479. It is, therefore, affected by
a remote code execution vulnerability.");
  # https://www.manageengine.com/products/desktop-central/remote-code-execution-vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b517c025");
  # https://www.manageengine.com/products/desktop-central/rce-vulnerability-cve-2020-10189.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9944baef");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central version 10 build 100479 or
later. Alternatively, apply the manual, vendor-supplied workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10189");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ManageEngine Desktop Central Java Deserialization');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_desktop_central_detect.nbin");
  script_require_keys("installed_sw/ManageEngine Desktop Central", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8020, 8383, 8040);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# Cannot know if manual workaround is in place.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

appname = "ManageEngine Desktop Central";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:8020);

install = get_single_install(
  app_name            : appname,
  port                : port,
  exit_if_unknown_ver : TRUE
);

dir = install["path"];
version = install["version"];
build   = install["build"];
ismsp   = install["MSP"];
rep_version = version;

install_url =  build_url(port:port, qs:dir);

if (ismsp) appname += " MSP";

if (build == UNKNOWN_VER)
  exit(0, "The build number of "+appname+" version " +rep_version+ " listening at " +install_url+ " could not be determined.");
else
  rep_version += " Build " + build;

build = int(build);
if (version =~ "^10(\.|$)" && build < 100479)
{
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + rep_version +
      '\n  Fixed version     : 10 Build 100479' +
      '\n';
    security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, rep_version);
