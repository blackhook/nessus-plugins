#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101110);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-4989", "CVE-2017-4990");
  script_bugtraq_id(99243);
  script_xref(name:"IAVB", value:"2017-B-0076");

  script_name(english:"EMC Avamar ADS / AVE 7.2.x < 7.2.1 Hotfix 277897 / 7.3.x < 7.3.1 Hotfix 276676 / 7.4.x < 7.4.1 Hotfix 279294 Multiple Vulnerabilities (ESA-2017-054)");
  script_summary(english:"Checks the version of EMC Avamar.");

  script_set_attribute(attribute:"synopsis", value:
"A backup solution running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the EMC Avamar Data
Store (ADS) or Avamar Virtual Edition (AVE) software running on the
remote host is 7.2.x prior to 7.2.1 Hotfix 277897 (7.2.1.32), 7.3.x
prior to 7.3.1 Hotfix 276676 (7.3.1.125), or 7.4.x prior to 7.4.1
Hotfix 279294 (7.4.1.58). It is, therefore, affected by multiple
vulnerabilities :

  - An authentication bypass vulnerability exists that
    allows an unauthenticated, remote attacker to bypass
    authentication and gain access to the system maintenance
    page. Note that this vulnerability does not affect the
    7.4.x version branch. (CVE-2017-4989)

  - A remote code execution vulnerability exists in the file
    upload feature of the system maintenance page due to
    improper validation of file types and extensions of
    uploaded files before being placed in a user-accessible
    path. An unauthenticated, remote attacker can exploit
    this to upload a specially crafted file and then request
    it in order to execute arbitrary code. Note that this
    vulnerability does not affect the 7.2.x version branch.
    (CVE-2017-4990)");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2017/Jun/att-40/ESA-2017-054.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC Avamar ADS / AVE version 7.2.1 Hotfix 277897 (7.2.1.32)
/ 7.3.1 Hotfix 276676 (7.3.1.125) / 7.4.1 Hotfix 279294 (7.4.1.58) or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4990");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar_data_store");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar_server_virtual_edition");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_avamar_server_detect.nbin", "emc_avamar_server_installed_nix.nbin");
  script_require_keys("installed_sw/EMC Avamar");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("http.inc");
include("misc_func.inc");

app = "EMC Avamar";
get_install_count(app_name:app, exit_if_zero:TRUE);

install = make_array();
port = 0;

if (get_kb_item("installed_sw/EMC Avamar/local"))
{
  install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
}
else
{
  port = get_http_port(default:443);
  install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
}

version    = install['version'];
version_ui = install['display_version'];
hotfixes   = install['Hotfixes'];

note = NULL;

if (version =~ "^7\.2\.[01]($|[^0-9])")
{
  fix_ver = '7.2.1.32';
  fix_hf  = '277897';
}
else if (version =~ "^7\.3\.[01]($|[^0-9])")
{
  fix_ver = '7.3.1.125';
  fix_hf  = '276676';
}
else if (version =~ "^7\.4\.[01]($|[^0-9])")
{
  fix_ver = '7.4.1.58';
  fix_hf  = '279294';
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app, version_ui);

if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) > 0)
  audit(AUDIT_INST_VER_NOT_VULN, app, version_ui);

if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == 0)
{
  # Remote detection cannot detect hotfix; only flag host if paranoid reporting is enabled
  if (port != 0)
  {
    if (report_paranoia < 2) audit(AUDIT_PARANOID);
    else
      note = "Note that Nessus was unable to remotely detect the hotfix.";
  }

  if (!empty_or_null(hotfixes))
  {
    hotfixes = split(hotfixes, sep:";", keep:FALSE);
    foreach hotfix (hotfixes)
    {
      if (fix_hf == hotfix)
        audit(AUDIT_INST_VER_NOT_VULN, app, version_ui + " HF" + hotfix);
    }
  }
}

report =
  '\n  Installed version : ' + version_ui +
  '\n  Fixed version     : ' + fix_ver + " HF" + fix_hf +
  '\n';

if (!isnull(note))
  report += note + '\n';

security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
