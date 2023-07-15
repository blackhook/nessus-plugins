#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65670);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-2560");
  script_bugtraq_id(58290);

  script_name(english:"Foscam 11.37.2.x < 11.37.2.49 Directory Traversal");
  script_summary(english:"Checks the version of Foscam");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Foscam IP Camera firmware 11.37.2.x < 11.37.2.49 on
the remote host has a directory traversal vulnerability.  A remote
attacker could exploit this to access the entire filesystem and wifi
credentials, for example, with a specially crafted request to retrieve
the host's /proc/kcore file. 

Note that Foscam cameras can be re-branded and re-sold by other vendors. 

Contact the vendor for vulnerability and firmware update information for
other firmware base versions.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2013/Mar/8");
  script_set_attribute(attribute:"solution", value:"Upgrade to Foscam 11.37.2.49 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:foscam:fi8919w");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");


  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foscam_detect.nasl");
  script_require_keys("www/foscam");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Foscam";

port = get_http_port(default:80, embedded:TRUE);

install = get_install_from_kb(appname:"foscam", port:port, exit_on_fail:TRUE);
dir = install["dir"];
version = install["ver"];
fix = "11.37.2.49";
install_url = build_url(port:port, qs:'/');

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, install_url);

if(version =~ "^11\.37\.2\." && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
