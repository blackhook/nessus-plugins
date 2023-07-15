#TRUSTED 6b443b454c87689479fd018f92808eff6e0aa320b34fc12e0c3047f937f8ebed30718c054011d4bc6730a1f4cdf3c01226528abaca9383cb58cc1ad9a28a6e15ab1dda3c881f8f5725572264ae484ac06421dc8a2049ca88b9e6a8c692327fc3ed8e2bf5ad1cb0923a97ee6ec99aa6bbfe4d7226d65d9302d9777978bd31881240b0a5f22f16976bb0f382e4d3ea0d7d85adf73a6ca6416bff2ec12919c16559c150cf227e1d6b857b4ebce2e28909d3d04d0071628e9e3376a6186a6799fbec98fded3be4b43eb3de8424f30be78f2b6f430cf6efa075eabf9b552c6afbf24dcacbfb6ddebeea3d25886db0f7b6b930da11ca5e22f8e3ff10149b64b513527a3a34024db2650e913590f5ac3bc5da40af431acf331aa2e134cd9d412d767321746878c939e2595b520d4559051cebb2a3a291d88031c31fd1a6b91e46adb0c4bae83c4d7a7d17c6c7cb80f744670b423f7741b4963651ecc6a87dc44a9c40989a58b5452d5847edfdee90f512cdcefc14e23b4da6cc7e9dc94db765191d5c521c834b66dbe04087f4eb31af42f9b4e59bd3d7b7d7ce9b27a4ad1c0841b9a5a72c1a34b75ee0884542a9a69f327e6cda6193aedc4204363f4f7e0083d59849d6015283ac4cb10735151d36a692b663251fc2bbe03e23f20de6f2cdbd96684d68545ae692188f9719d0ba12ce17f03f72cc366bc9feb34553509b076556c58e3c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95921);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2016-0909");
  script_bugtraq_id(93788);

  script_name(english:"EMC Avamar ADS / AVE < 7.3.0 Hotfix 263301 PostgreSQL Command Local Privilege Escalation (ESA-2016-111)");
  script_summary(english:"Checks the version and configuration of EMC Avamar.");

  script_set_attribute(attribute:"synopsis", value:
"A backup solution running on the remote host is affected by a local
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the EMC Avamar Data
Store (ADS) or Avamar Virtual Edition (AVE) software running on the
remote host is a version prior to 7.3.0 Hotfix 263301 (7.3.0.233),
or the configuration is not patched. It is, therefore, affected by a
local privilege escalation vulnerability that allows a local attacker
to execute arbitrary PostgreSQL commands and thereby gain elevated
privileged.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2016/Oct/att-45/ESA-2016-111.txt");
  script_set_attribute(attribute:"see_also", value:"https://support.emc.com/kb/486276");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC Avamar ADS / AVE version 7.3.0 Hotfix 263301
(7.3.0.233) and apply the configuration changes documented in
KB486276.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0909");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar_data_store");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar_server_virtual_edition");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_avamar_server_detect.nbin", "emc_avamar_server_installed_nix.nbin");
  script_require_keys("installed_sw/EMC Avamar");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("telnet_func.inc");
include("http.inc");
include("misc_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

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

fix_ver = '7.3.0.233';
fix_hf  = '263301';

vuln         = FALSE; 
config_check = FALSE;

report_fix    = NULL;
insecure_file = NULL;

if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) < 0)
  vuln = TRUE;

# Remote checks cannot check the configuration or hotfix reliably
if (!vuln && port != 0)
  exit(0, "The "+app+" "+version_ui+" install listening on port "+port+" may be affected but Nessus was unable to test for the issue. Please provide valid credentials to test for the issue.");

# Check for hotfixes
if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == 0)
{
  if (empty_or_null(hotfixes))
    vuln = TRUE;
  else
  {
    hotfixes = split(hotfixes, sep:";", keep:FALSE);
    foreach hotfix (hotfixes)
    {
      if (fix_hf == hotfix)
      {
        config_check = TRUE;
        version_ui += " HF" + fix_hf;
      }
    }
    if (!config_check) vuln = TRUE;
  } 
}
# For versions later than 7.3.0.233 HF263301 we still need to check the configs
else if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) > 0)
  config_check = TRUE;

# Only check configuration if 7.3.0.233 HF263301 or higher is detected
# Look for configurations from KB486276 (https://support.emc.com/kb/486276)
if (config_check)
{
  if (!get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

  # Select transport
  if (islocalhost())
  {
    if (!defined_func("pread"))
      exit(1, "'pread()' is not defined.");
    info_t = INFO_LOCAL;
  }
  else
  {
    sock_g = ssh_open_connection();
    if (!sock_g)
      audit(AUDIT_FN_FAIL, 'ssh_open_connection');
    info_t = INFO_SSH;
  }

  config_check = TRUE;
  path = "/usr/local/avamar/var/mc/server_data/";

  configs = make_array(
    "postgres/data/pg_hba.conf",
      [make_list("local all all peer map=mcdb",
                "hostssl all all samehost cert clientcert=1",
                "host mcdb viewuser 0.0.0.0/0 md5",
                "host mcdb viewuser ::0/0 md5"), "# PostgreSQL"],
    "postgres/data/pg_ident.conf",
      [make_list("mcdb admin admin",
                "mcdb admin viewuser",
                "mcdb root admin",
                "mcdb root viewuser"), "# PostgreSQL"],
    "postgres/data/postgresql.conf",
      [make_list("ssl = on"), "# PostgreSQL"],
    "prefs/mcserver.xml",
      [make_list('<entry key="database_sslmode" value="true" />'), "com.avamar.asn"]
  );

  foreach subpath (keys(configs))
  {
    content = info_send_cmd(cmd:"cat " + path + subpath);
    foreach config (configs[subpath][0])
    {
      conf_pattern = configs[subpath][1];

      pattern = str_replace(string:config, find:" ", replace:'\\s+');
      pattern = '^\\s*' + pattern + '\\s*';
      if (conf_pattern >< content && !preg(string:content, pattern:pattern, icase:TRUE, multiline:TRUE))
      {
        insecure_file = path + subpath;
        report_fix = "Apply the configurations as documented in KB486276." +
          '\n  Insecure file     : ' + insecure_file ;         
        vuln = TRUE;
        break;
      }
    }
    if (vuln) break;
  }
  if (info_t == INFO_SSH) ssh_close_connection();
}
else
{
  report_fix =
    fix_ver + " HF" + fix_hf + " and apply the configurations as documented in KB486276.";
}

if (!vuln)
  audit(AUDIT_INST_VER_NOT_VULN, app, version_ui);

report =
  '\n  Installed version : ' + version_ui +
  '\n  Fixed version     : ' + report_fix +
  '\n';

security_report_v4(
  extra    : report,
  port     : port,
  severity : SECURITY_HOLE
);
