#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100963);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-8947");
  script_bugtraq_id(98960);
  script_xref(name:"HP", value:"HPESBGN03758");
  script_xref(name:"ZDI", value:"ZDI-17-393");

  script_name(english:"HPE UCMDB 'UploadFileOnUIServerServlet' Servlet Path Handling RCE (HPESBGN03758)");
  script_summary(english:"Checks the UCMDB Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP Universal Configuration Management Database Server
(UCMDB) running on the remote web server is missing a security patch.
It is, therefore, affected by a remote code execution vulnerability in
the 'UploadFileOnUIServerServlet' servlet due to improper handling of
user-supplied paths. An unauthenticated, remote attacker can exploit
this, via a specially crafted request, to execute arbitrary code with
SYSTEM privileges.");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbgn03758en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0aa6e69");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-17-393/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HPE UCMDB 10.11 CUP9 / 10.22 CUP5 + Hotfix / 10.32 or later
as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8947");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:universal_configuration_management_database");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_ucmdb_server_detect.nbin");
  script_require_keys("installed_sw/HP Universal Configuration Management Database Server", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

# Flag this as paranoid since we don't exploit the vulnerability
# and we haven't yet gotten access to a patch.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "HP Universal Configuration Management Database Server";
get_install_count(app_name:app_name, exit_if_zero:TRUE);
port = get_http_port(default:8080);

install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
url = build_url(port:port, qs:install['url']);

# Only versions of 10 known to have the problem
if (version !~ "^10[^0-9]")
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);
}

fix = NULL;
if (version =~ "^10\.(10|11)[^0-9]*$")
{
  fix = "10.11 CUP9";
}
else if (version =~ "^10\.(20|21|22)[^0-9]*$")
{
  fix = "10.22 CUP5 plus Hotfix";
}
else if (version =~ "^10\.(30|31)[^0-9]*$")
{
  fix = "10.32";
}
else
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);
}

report =
  '\n URL               : '+url+
  '\n Installed version : '+version+
  '\n Fixed version     : '+fix+
  '\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
