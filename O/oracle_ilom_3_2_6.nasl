#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104047);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2016-6304",
    "CVE-2016-7431",
    "CVE-2017-3588",
    "CVE-2017-10099",
    "CVE-2017-10194",
    "CVE-2017-10260",
    "CVE-2017-10265",
    "CVE-2017-10275"
  );
  script_bugtraq_id(
    93150,
    94454,
    101426,
    101431,
    101435,
    101437,
    101442,
    101445
  );

  script_name(english:"Oracle Integrated Lights Out Manager (ILOM) < 3.2.6 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks DCNM version number");

  script_set_attribute(attribute:"synopsis", value:
"A network management system installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Oracle
Integrated Lights Out Manager (ILOM) is affected by multiple vulnerabilities
as described in the advisory.");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e07fa0e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Integrated Lights Out Manager (ILOM) 3.2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10265");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:embedded_lights_out_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:integrated_lights_out_manager_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_ilom_web_detect.nasl");
  script_require_keys("installed_sw/ilom", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_install_count(app_name:"ilom", exit_if_zero:TRUE);

port = get_http_port(default:443);
app = "Oracle ILOM";

install = get_single_install(
  app_name : "ilom",
  port     : port,
  exit_if_unknown_ver : TRUE
  );
version = install["version"];
path = install["path"];
url = build_url(port:port, qs:path);

fix = "3.2.6";

if (ver_compare(ver:version, fix:fix) == -1)
{
  report =
  '\n  URL               : ' + url +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);

