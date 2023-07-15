#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109914);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-6492", "CVE-2018-6493");
  script_bugtraq_id(104131);
  script_xref(name:"IAVB", value:"2018-B-0064");

  script_name(english:"HP Network Automation 10.0x < 10.00.023 / 10.1x < 10.11.06 / 10.2x < 10.21.05 / 10.3x < 10.30.03 / 10.4x < 10.40.01 / 10.5x < 10.50.01 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HP Network Automation.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The HP Network Automation application running on the remote host is
version 10.0x prior to 10.00.023; 10.1x prior to 10.11.06;
10.2x prior to 10.21.05; 10.3x prior to 10.30.03;
10.4x prior to 10.40.01; or 10.5x prior to 10.50.01. It is, therefore,
affected by multiple vulnerabilities
Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://softwaresupport.softwaregrp.com/document/-/facetsearch/document/KM03158014
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8c572d6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Network Automation version 10.00.023 / 10.11.06 /
10.21.05 / 10.30.03 / 10.40.01 / 10.50.01 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6493");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:network_automation");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_network_automation_detect.nbin");
  script_require_keys("installed_sw/HP Network Automation");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "HP Network Automation";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port    = get_http_port(default:443);
install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
url     = build_url(port:port,qs:install['path']);

fix = NULL;
vuln = FALSE;

# Patch number 10.00.023, for NA Version 10.0x
if (version =~ "^10\.00(\.|$)")
{
  fix = "10.00.023";
}
# Patch number 10.11.06, for NA version 10.1x
else if (version =~ "^10\.1[0-1](\.|$)")
{
  fix = "10.11.06";
}
# Patch number 10.21.05, for NA version 10.2x
else if (version =~ "^10\.2[0-1](\.|$)")
{
  fix = "10.21.05";
}
# Patch number 10.30.03, for NA version 10.3x
else if (version =~ "^10\.30(\.|$)")
{
  fix = "10.30.03";
}
# Patch number 10.40.01, for NA version 10.4x
else if (version =~ "^10\.40(\.|$)")
{
  fix = "10.40.01";
}
# Patch number 10.50.01 - for NA version 10.5x
else if (version =~ "^10\.50(\.|$)")
{
  fix = "10.50.01";
}

if (isnull(fix))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);

if (!vuln)
{
  if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0 )
  vuln = TRUE;
}

if (vuln)
{
  items = make_array("URL", url,
                     "Installed version", version,
                     "Fixed version", fix
                    );
  order = make_list("URL", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, xss:TRUE, sqli:TRUE);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);
