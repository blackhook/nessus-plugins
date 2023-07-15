#TRUSTED 2888944431e83f26adca288799d6799656e05c2f199c5128a5fe0e67b0482861b7243d14d6cfb799ce2824b203d167fabe51e4c0bf58bf3c2a1d9282539f39c9561fd3820e70363dbf6617c1adfcc7600f700e065f82fe76fca8c6e36629b310d3bb15140be38c2a79545f628d1de97318d139e35a3c02093d3e1112a962ae0324086a379e6e628b730570f3d13715beaadac773b254c18f5dff37d9dd6d7610d3f9ad53e15fcb29f1e28ace3f1636752d229dce69c146793b2032e5dae0787fd087ce2eb1850308695ee972ad9c614ba7f1a796c6f10b4cf1627796f4fb6556deae71b722a407974e64878416f19954a251ed9ab07f875fa62386fc67577d95beace1443dca9ccc9a0a56a316519418e7ddec2aeef1fe54357d908219a0b131eff5ef9a076897ec0286b9f2906f8d24ac83dc98fc789cd0d81af9e6d33f8bc3ce01dfa116fbd50d18f7b3f7c68280f49adea50b623d13b4c8e06588bd47247929377b2b7953566cbcefa2721b19a6ea37bea9be59ea1567504906fff29b2cd4cdf220e7549e4703d0278b571d5ecc727f0d10fbd78d129d4c8c5e572d19a56c1a0fe55637f2025a0b0d67e6f715b7e7cd95f998dcff3a2a126773efaa8fe85c8391f63540d51eac9e828842f27d05fd6b5e618eb911b57f24a43ef2b5631d9539e7cacfed7e631112402283306a5834e75d72f17cb977f0b3f4eeb34f622026
#
# (C) Tenable Network Security, Inc.


include("compat.inc");

if (description)
{
  script_id(104361);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2017-11508");

  script_name(english:"Tenable SecurityCenter 5.5.0 <= 5.5.2 SQLi (TNS-2017-13)");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by 
a SQL injection flaw.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter
application installed on the remote host is affected by a SQL 
injection flaw.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2017-13");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor advisory or 
upgrade to Tenable SecurityCenter version 5.6.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11508");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
    enable_ssh_wrappers();
else disable_ssh_wrappers();

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(version))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  version = install["version"];
}
vuln = FALSE;

# Affects versions 5.5.0 - 5.5.2
if (version =~ "^5\.5\.[0-2]$")
{
    # Establish running of local commands
    if ( islocalhost() )
    {
      if ( ! defined_func("pread") ) audit(AUDIT_NOT_DETECT, "pread");
        info_t = INFO_LOCAL;
    }
    else
    {
      sock_g = ssh_open_connection();
      if (! sock_g) audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
        info_t = INFO_SSH;
    }

    # Check scan.php file if it contains the patched lines
    res = info_send_cmd(cmd:"cat /opt/sc/src/tools/scan.php");
    if (info_t == INFO_SSH) ssh_close_connection();
    if (! res || 'setStatus(SCAN_PREPARING);' >!< res) exit(1, "The command 'cat /opt/sc/src/tools/scan.php' failed.");
    if ('$stmt->execute($sqlParams[$sqlIndex]);' >!< res)
    {
      vuln = TRUE;
      fix = "Apply the patch referenced in the TNS-2017-13 advisory or upgrade to version 5.6.0 or later.";
    }
}

if (vuln)
{
    report =
          '\n  Installed version  : ' + version +
              '\n  Fixed version      : ' + fix + '\n';
      security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, sqli:TRUE);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);

