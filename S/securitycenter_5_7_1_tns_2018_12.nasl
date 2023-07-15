#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117672);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

 
  script_cve_id(
    "CVE-2018-0732",
    "CVE-2018-0737",
    "CVE-2018-7584",
    "CVE-2018-10545",
    "CVE-2018-10546",
    "CVE-2018-10547",
    "CVE-2018-10548",
    "CVE-2018-10549",
    "CVE-2018-14851",
    "CVE-2018-14883",
    "CVE-2018-15132"
  );
  script_bugtraq_id(
    103204,
    103766,
    104019,
    104020,
    104022,
    105205
  );

  script_name(english:"Tenable SecurityCenter < 5.7.1 Multiple Vulnerabilities (TNS-2018-12)");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter
application installed on the remote host is prior to 5.7.1. It is,
therefore, affected by multiple vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2018-12");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 5.7.1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7584");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");


  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

version = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(version))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  version = install["version"];
}
fix = "5.7.1";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  items = make_array(
    "Installed version", version,
    "Fixed version", fix
  );
  order = make_list("Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);
