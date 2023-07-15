#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78393);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-5285");
  script_bugtraq_id(69582);

  script_name(english:"TIBCO Spotfire Server Authentication Module Unspecified Privilege Escalation");
  script_summary(english:"Checks for TIBCO Spotfire Server.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of TIBCO Spotfire Server that is
affected by a privilege escalation vulnerability due to an unspecified
flaw in the Authentication Module. A remote attacker can exploit this
vulnerability to access sensitive information and modify data.");
  # http://www.tibco.com/assets/bltdb348db4de625c6f/2014-006-Spotfire-advisory-cm-including3.X_v4.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b96c7ffb");
  # https://www.tibco.com/support/advisories/2014/09/tibco-security-advisory-september-03-2014-tibco-spotfire-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14fe1caa");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tibco:spotfire_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencies("tibco_spotfire_server_detect.nbin");
  script_require_keys("installed_sw/TIBCO Spotfire Server");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80);

app_name = "TIBCO Spotfire Server";
install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);

url = build_url(port:port, qs:install['path']);
version = install['version'];

fix = FALSE;

if (version =~ "^4\.5\.")
  fix = "4.5.2";
else if (version =~ "^5\.0\.")
  fix = "5.0.3";
else if (version =~ "^5\.5\.")
  fix = "5.5.2";
else if (version =~ "^6\.0\.")
  fix = "6.0.3";
else if (version =~ "^6\.5\.")
  fix = "6.5.1";
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);
