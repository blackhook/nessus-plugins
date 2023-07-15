#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88843);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2015-6863", "CVE-2015-6864");
  script_bugtraq_id(80526);
  script_xref(name:"HP", value:"HPSBGN03532");
  script_xref(name:"HP", value:"SSRT102159");
  script_xref(name:"HP", value:"emr_na-c04941487");

  script_name(english:"HP ArcSight Logger < 6.1P1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HP ArcSight Logger.");

  script_set_attribute(attribute:"synopsis", value:
"The application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP ArcSight Logger installed on the remote host is
prior to 6.1P1. It is, therefore, affected by multiple vulnerabilities
in the Intellicus and client-certificate upload components due to
improper validation of user-supplied input. A remote attacker can
exploit these to bypass security restrictions, resulting in the
uploading or deletion of files or the execution of arbitrary code.");
  # https://support.hpe.com/hpsc/doc/public/display?calledBy=&docId=emr_na-c04941487
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36337330");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP ArcSight Logger version 6.1P1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6863");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:arcsight_logger");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arcsight_logger_installed_linux.nasl");
  script_require_keys("installed_sw/ArcSight Logger");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "ArcSight Logger";
port = 0;

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver = install['version'];
path = install['path'];
display_ver = install['display_version'];

fix = '6.1.0.7504.1';
display_fix = '6.1.0.7504.1 (6.1P1)';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, app, display_ver, path);

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + display_ver +
  '\n  Fixed version     : ' + display_fix + '\n';

security_report_v4(port: port, severity: SECURITY_HOLE, extra: report);
