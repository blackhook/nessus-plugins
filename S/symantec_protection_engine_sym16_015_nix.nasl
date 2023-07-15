#TRUSTED 2f897924bca01bc5a93dc680de581d0c5794a66c3f1cd1cea98070f392fdb6b93d7ffaad2ed8113602ac17fd58cdcd3caf8589e061dacf0e8def569146f81ebe96e96d6eb04c746f6c09a79b3f4b8f2553e87cf7324773ee44e00f54408a8b070c1485539f12b5229b87906147d58058e1f71beba018d9bec9e596715bf9a7d165c4830d55ec7185ea85872128d0e0e560a13148b3dc3df189844f9c8b7dc387c504735196f7eabd6089cef263971dcc2a0e54d31af4e6a3873b5d38e7180940707639bb6549ce13f6b386bf4262b2005dba0c29c06a0094dbc721189421932d597b233f4ea56b7fafd98059604f780953f6ef14f98f1e3451952f98dbdd7286167546559f68767e773827aaeed9646f71b2f196844f56f9d5f23edc9bad052e83f50f6c2e0180bb34d6f38332bf277eaf319c18cef8dc96b8231097e3b431256437066a0244e47eb4610dfc2fcda39f7b58a14ec605de0e5d13b4b71a37e008a3d8c51e24fa15a2c81b289fc3af35a3b818de8d5c0059f56427ce8797f6018019295d54b39c0f50206f13ca615c3a28c311f25cd811b34823dd83580fdf1cb892518e3058dc5f67124d64d8b5e20a06a62c2cb933793ebff85f04a0f01f3aec5789bfe7c31d529fc64b9013ab494e356b344c012cd6508937c3bddd2d0c8c7e622a5f4ad5cbdcd1b73fce0f7efa22986c788f31e6d241f030ff4591973b66b2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93655);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2016-5309", "CVE-2016-5310");
  script_bugtraq_id(92866, 92868);
  script_xref(name:"IAVA", value:"2016-A-0256");

  script_name(english:"Symantec Protection Engine 7.0.x < 7.0.5 HF02 / 7.5.x < 7.5.5 HF01 / 7.8.x < 7.8.0 HF03 Multiple DoS (SYM16-015) (Linux)");
  script_summary(english:"Checks the version of Symantec Protection Engine.");

  script_set_attribute(attribute:"synopsis", value:
"A security application installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Protection Engine (SPE) installed on the
remote Linux host is 7.0.x prior to 7.0.5 hotfix 02, 7.5.x prior to
7.5.5 hotifx 01, or 7.8.x prior to 7.8.0 hotifx 03. It is, therefore,
affected by multiple denial of service vulnerabilities :

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
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/article.INFO3791.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Protection Engine (SPE) version 7.0.5 HF02 / 7.5.5
HF01 / 7.8.0 HF03 or later per the vendor advisory.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:protection_engine");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_protection_engine.nbin");
  script_require_keys("installed_sw/Symantec Protection Engine");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

app = 'Symantec Protection Engine';
port = NULL;
function check_hf(path)
{
  local_var cmd, ret, buf, match, ver;
  local_var line, matches, vuln;

  vuln = FALSE;
  cmd = "cat -v " + path + "/bin/libdec2.so";

  if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

  port = kb_ssh_transport();
  if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

  ret = ssh_open_connection();
  if (!ret) exit(1, 'ssh_open_connection() failed.');


  buf = ssh_cmd(cmd:cmd);
  ssh_close_connection();
  if(!empty_or_null(buf)){
    match = eregmatch(pattern:"Decomposer\^@(\d\.\d\.\d\.\d)",string:buf);
    ver = match[1];
    if(ver_compare(ver:ver, fix:"5.4.7.5", strict:FALSE) < 0) vuln = TRUE;
  }
  else audit(AUDIT_UNKNOWN_APP_VER, "Symantec Protection Engine: Decomposer Engine");
  return vuln;
}

install = get_single_install(app_name:app);
version = install["version"];
path = install["path"];
path = chomp(path);

fix = NULL;

if (version =~ "^7\.0\.[0-9.]+$")
{
  if (
    version =~ "^7\.0\.5\." &&
    check_hf(path:path)
  ) fix = "7.0.5.x with HF02 applied";

  if (version =~ "^7\.0\.[0-4]\.")
    fix = "7.0.5.x with HF02 applied";
}
else if (version =~ "^7\.5\.[0-9.]+$")
{
  if (
    version =~ "^7\.5\.5\." &&
    check_hf(path:path)
  ) fix = "7.5.5.x with HF01 applied";

  if (version =~ "^7\.5\.[0-4]\.")
    fix = "7.5.5.x with HF01 applied";
}
else if (version =~ "^7\.8\.[0-9.]+$")
{
  if (
    version =~ "^7\.8\.0\." &&
    check_hf(path:path)
  ) fix = "7.8.0.x with HF03 applied";
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

if (!empty_or_null(fix))
{
  report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", version,
      "Fixed version", fix
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version")
  );

  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
