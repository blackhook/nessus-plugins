#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93658);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2016-5309", "CVE-2016-5310");
  script_bugtraq_id(92866, 92868);
  script_xref(name:"IAVA", value:"2016-A-0257");

  script_name(english:"Symantec Protection for SharePoint Servers 6.0.3 - 6.0.5 < HF2.5 / 6.0.6 < HF2.6 / 6.0.7 < HF2.7 Multiple DoS (SYM16-015)");
  script_summary(english:"Checks the version of Symantec Protection for SharePoint Servers.");

  script_set_attribute(attribute:"synopsis", value:
"A security application installed on the remote host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Protection for SharePoint Servers (SPSS)
installed on the remote host is 6.0.3 to 6.0.5 prior to hotfix 2.5,
6.0.6 prior to hotfix 2.6, or 6.0.7 prior to hotfix 2.7. It is,
therefore, affected by multiple denial of service vulnerabilities :

  - A denial of service vulnerability exists in the
    decomposer engine due to an out-of-bounds read error
    that occurs when decompressing RAR archives. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted RAR file, to crash the application.
    (CVE-2016-5309)

  - A denial of service vulnerability exists in the
    decomposer engine due to memory corruption issue that
    occurs when decompressing RAR archives. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted RAR file, to crash the application.
    (CVE-2016-5310)");
  # https://support.symantec.com/en_US/article.SYMSA1379.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0df20c4e");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/article.INFO3795.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5310");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:protection_for_sharepoint_servers");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_scan_engine_installed.nasl", "symantec_protection_sharepoint_servers.nbin");
  script_require_keys("SMB/symantec_scan_engine/Installed", "installed_sw/Symantec Protection for SharePoint Servers");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("install_func.inc");

function check_hf(path, dllversion)
{
  local_var loc, locs, content;
  local_var line, matches, vuln;

  vuln = FALSE;

  hotfix_check_fversion_init();

  locs  = make_list(path, path + "Definitions\Decomposer\");

  foreach loc(locs)
  {
    if (hotfix_check_fversion(file:"dec2.dll", version:dllversion, path:loc))
    {
      vuln = TRUE;
      break;
    }
  }

  hotfix_check_fversion_end();

  return vuln;
}

spepath = get_kb_item("Symantec/Symantec Protection Engine/Path");
if (empty_or_null(spepath))
  exit(0, "Cannot determine path to Symantec Protection Engine.");
app = "Symantec Protection for SharePoint Servers";
install = get_single_install(app_name:app);
version = install["version"];
path = install["path"];

# audit if decomposer engine is not affected
engineVer = "5.4.7.5";
if (!check_hf(path:spepath, dllversion:engineVer))
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

fix = NULL;
if (version =~ "^6\.0\.[3-5]($|[^0-9])")
  fix = "SPSS 6.0.3 to 6.0.5 HF 2.5";
else if (version =~ "^6\.0\.6($|[^0-9])")
  fix = "SPSS 6.0.6 HF 2.6";
else if (version =~ "^6\.0\.7($|[^0-9])")
  fix = "SPSS 6.0.7 HF 2.7";
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

if (!isnull(fix))
{
  port = kb_smb_transport();
  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
