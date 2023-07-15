#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104354);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-14090",
    "CVE-2017-14091",
    "CVE-2017-14092",
    "CVE-2017-14093"
  );

  script_name(english:"Trend Micro ScanMail for Exchange 12.x < SP1 Patch 1 CP1755");
  script_summary(english:"Checks the version of Trend Micro ScanMail.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an email security application installed
with multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Trend Micro ScanMail for Exchange (SMEX) installed on
the remote Windows host is affected by multiple vulnerabilities,
including cross-site scripting (XSS) and weak anti cross-site request
forgery (CSRF).");
  # https://success.trendmicro.com/solution/1118486-security-bulletin-trend-micro-scanmail-for-exchange-12-0-multiple-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2cbee04e");
  # https://www.secureauth.com/labs/advisories/trend-micro-scanmail-microsoft-exchange-multiple-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?386d498e");
  script_set_attribute(attribute:"solution", value:
"Apply SP1 Patch 1 CP1755 as referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14091");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:scanmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_smex_installed.nbin");
  script_require_keys("installed_sw/Trend Micro ScanMail for Exchange", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'Trend Micro ScanMail for Exchange';
install = get_single_install(app_name:appname,exit_if_unknown_ver:TRUE);
version = install["version"];
patch   = int(install["Patch Build"]);
spack   = int(install["Service Pack"]);
path    = install["path"];
dllfix  = FALSE;
port    = kb_smb_transport();

if(version =~ "^12\.0\.")
  dllfix = "12.0.0.1755";
else
  audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);

# File Check
dll = hotfix_append_path(path:path, value:"servPolicyController.dll");
dllver = hotfix_get_fversion(path:dll);
hotfix_handle_error(
  error_code   : dllver['error'], 
  file         : dll, 
  appname      : appname, 
  exit_on_fail : TRUE
);
dllver = join(dllver['value'], sep:'.');
hotfix_check_fversion_end();

if(ver_compare(ver:dllver,fix:dllfix,strict:FALSE) < 0)
{
  report =
  '\n  File              : ' + dll +
  '\n  Installed version : ' + dllver +
  '\n  Fixed version     : ' + dllfix + '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report, xss:TRUE, xsrf:TRUE);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
