#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130465);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2019-3765");
  script_xref(name:"IAVB", value:"2019-B-0083");

  script_name(english:"EMC Avamar Server Incorrect Permission Assignment Vulnerability (DSA-2019-138)");
  script_summary(english:"Checks the version of EMC Avamar.");

  script_set_attribute(attribute:"synopsis", value:
"A backup solution running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the EMC Avamar Server versions
software running on the remote host is 7.4.1, 7.5.0, 7.5.1, 18.2, or 19.1 and missing the
appropriate hotfixes.  A remote authenticated attacker can potentially exploit 
this vulnerability to view or modify sensitive backup data.");
  # https://www.dell.com/support/security/en-us/details/537649/DSA-2019-138-Dell-EMC-Avamar-Incorrect-Permission-Assignment-for-Critical-Resource-Vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a63de989");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC Avamar Server version 7.4.1 Hotfix 311510 (7.4.1.58)
7.5.0 Hotfix 311509 (7.5.0.183) / 7.5.1 Hotfix 311508 (7.5.1.101) /
18.2 Hotfix 311511 (18.2.0.134) / 19.1 Hotfix 311512 (19.1.0.38)  or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3765");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar_server_virtual_edition");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (version =~ "^7\.4\.[1]($|[^0-9])")
{
  fix_ver = '7.4.1.58';
  fix_hf  = '311510';
}
else if (version =~ "^7\.5\.[0]($|[^0-9])")
{
  fix_ver = '7.5.0.183';
  fix_hf  = '311509';
}
else if (version =~ "^7\.5\.[1]($|[^0-9])")
{
  fix_ver = '7.5.1.101';
  fix_hf  = '311508';
}
else if (version =~ "^18\.2($|[^0-9])")
{
  fix_ver = '18.2.0.134';
  fix_hf  = '311511';
}
else if (version =~ "^19\.1($|[^0-9])")
{
  fix_ver = '19.1.0.38';
  fix_hf  = '311512';
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

security_report_v4(extra:report, port:port, severity:SECURITY_WARNING);
