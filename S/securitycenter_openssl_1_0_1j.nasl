#TRUSTED 09f339a9f1cf06bba57b82145bdc796a8ab246a9ba0368af87878e03d88861823a59ecb1765747f5d0ba73cf846053eee82b240496d8484c7e4ccaf37e92ecf7718649bab676fd202c73874a07cb60553e18cb072682c4f118bd0b373b7a96231df74b8acfc1ad92228aa8ef7d1b8742fc6dd87c509b20f65d98256d57dd5a8365e49246d5996f92dde725398edd636fbdaff4e7acd4d1c444f54290e08eb1ba66f083213f3ba7a6980cbecc40da7b72a2def7e3e7df6141a55454c7a51a53dba0d0781e02c2920008ec4814c885ac0749518b862bc7b0dcc2466c232bc6e38a7e2055ff6670b3fe495d61134cfb06786f471ee386d7e2039b8018a5a07e0f18bbd3b016182f98429ab472f49f0135ada471838a05cadeb3737cf3253b918b2a8a777761b55394b3449979a476259e74ab55c13dae340189a58ff2449e2c80239d0fe62a9ab986b3c5e9ac9ec60c600c9e9da2b177a0f7b030248ad97ce646acbc70b8eb8009f6d8e5451eaadcad7c9ca67458902c119d69636a1441cf04f7a9a617acfc25531066a6040c6fb724d4559f4dd48f7f062c3c076aa564c959dd58025819b2d5cdfff9590872a532db531eac1714f12c1471a70bf9cdd9ae62f3651c7315f8dfa5c019b2fa0e2c80a1a70620e752260a9b2a4814077e1bc773dbc5580dc0ddbc6940ce0e4ca0b3c171a0130b01613ad1dcab9f10b3809cc8b95630
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80303);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2014-3513", "CVE-2014-3567");
  script_bugtraq_id(70584, 70586);

  script_name(english:"Tenable SecurityCenter Multiple DoS (TNS-2014-11)");
  script_summary(english:"Checks the version of OpenSSL in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The SecurityCenter application installed on the remote host is
affected by multiple denial of service vulnerabilities in the bundled
OpenSSL library. The library is version 1.0.1 prior to 1.0.1j. It is,
therefore, affected by the following vulnerabilities :

  - A memory leak exists in the DTLS SRTP extension parsing
    code. A remote attacker can exploit this issue, using a
    specially crafted handshake message, to cause excessive
    memory consumption, resulting in a denial of service
    condition. (CVE-2014-3513)

  - A memory leak exists in the SSL, TLS, and DTLS servers
    related to session ticket handling. A remote attacker
    can exploit this, using a large number of invalid
    session tickets, to cause a denial of service condition.
    (CVE-2014-3567)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2014-11");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/openssl-1.0.1-notes.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20141015.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter");

  exit(0);
}

include("openssl_version.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

get_kb_item_or_exit("Host/local_checks_enabled");
sc_ver = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(sc_ver))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  sc_ver = install["version"];
}
if (! preg(pattern:"^4\.[6-9]", string:sc_ver)) audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

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

fix = "1.0.1j";
pattern = "OpenSSL (\d+(?:\.\d+)*(-beta\d+|[a-z]*))";

# Check version
line = info_send_cmd(cmd:"/opt/sc4/support/bin/openssl version");
if (info_t == INFO_SSH) ssh_close_connection();

if (! line) audit(AUDIT_VER_FAIL, "/opt/sc4/support/bin/openssl");
match = pregmatch(pattern:pattern, string:line);
if (isnull(match)) audit(AUDIT_UNKNOWN_APP_VER, line);
version = match[1];

# Check if vulnerable. Same branch only flags if the 1.0.1 matches,
# min check makes betas not vuln.
if (openssl_ver_cmp(ver:version, fix:fix, same_branch:TRUE, is_min_check:FALSE) < 0)
{
  report = '\n' +
    '\n  SecurityCenter version         : ' + sc_ver +
    '\n  SecurityCenter OpenSSL version : ' + version +
    '\n  Fixed OpenSSL version          : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OpenSSL (within SecurityCenter)", version);
