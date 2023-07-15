#TRUSTED 2bb85d59b2588372a9e8f323f12543ad1dd77154d2a14d8d7201e069801dbfe4c1a7a3cc261bcf1fda5eba436248393db3de21e7f467f263da98005303870422341761eb7ab605b274b6600320213262281321c059525455a9353ed6baa9870973cf0ccd2fc534ba1d0d1a438b40f98c15933e19d5489b8b39b80bc7a956ad57cc31835f015d05413cb9f00aef0af53b616cb340526ed5f6c3f21e2b21925362db1b52472f8f952863e3c2b94a430b03e750dedc5bc2334996de6665ec0380589877f905128c4c5e77563c5c09ca20a69c6f038477a9e5a82971747dafcffabcc9cfd0eebaaf16c09049082882afa5aec6a2f63601e67ca02c3229f419ee7b2f444124b489a9615a884b23c7ad9446b177f4b5fe6ea8873eaee2fdea51a191a025c887c252382a468ef84564cfab8a2928f742af743f178f1ea69bdfa14addad4d4506b9c1e34d8844f0c1ab6a8390e7c53eda6409aac8ab0a7055134644cf1d1c22ef1b360ee1ec303cbe29757fee5457983851b29e461ab6dcd9d6acbbd5dbca39bdffebb6c27bd0af16a6e8cde915a39c5c0ea0c50b659aac91dd6c6f5d8d356726d766a399192c19c06011b61e2f478087b403c9d1c52cb385fee30df535ca862fb41d78c0fa61e2cdec2ad4726cd93375c9af5395a28b788504afb9347e6a972cecf1299fcee12143ec27dca45c9dedb278222807b9cf9fd3ba2db3c2ef
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85565);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2015-1793");
  script_bugtraq_id(75652);

  script_name(english:"Tenable SecurityCenter Alternative Certificate Validation Bypass Vulnerability (TNS-2015-08)");
  script_summary(english:"Checks the version of OpenSSL in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by a certificate validation bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The SecurityCenter application installed on the remote host is
affected by a certificate validation bypass vulnerability in the
bundled OpenSSL library. The library is version 1.0.1n or later and
prior to 1.0.1p. It is, therefore, affected by a flaw in the
X509_verify_cert() function that is triggered when locating alternate
certificate chains in cases where the first attempt to build such a
chain fails. A remote attacker can exploit this to cause certain
certificate checks to be bypassed, resulting in an invalid certificate
being considered valid.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2015-08");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150709.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1793");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter", "Host/local_checks_enabled");

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

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
sc_ver = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(sc_ver))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  sc_ver = install["version"];
}
if (! preg(pattern:"^(4\.[6-8]\.|5\.0\.[0-1])", string:sc_ver)) audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

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

fixes = make_list("1.0.1p", "1.0.2d");
cutoffs = make_list("1.0.1n", "1.0.2b");
pattern = "OpenSSL (\d+(?:\.\d+)*(-beta\d+|[a-z]*))";

# Check version
line = info_send_cmd(cmd:"/opt/sc4/support/bin/openssl version");
if (!line) line = info_send_cmd(cmd:"/opt/sc/support/bin/openssl version");
if (info_t == INFO_SSH) ssh_close_connection();

if (!line) audit(AUDIT_UNKNOWN_APP_VER, "OpenSSL (within SecurityCenter)");
match = pregmatch(pattern:pattern, string:line);
if (isnull(match)) audit(AUDIT_UNKNOWN_APP_VER, line);
version = match[1];

fix = NULL;

for ( i=0; i<2; i++)
{
  if (
    openssl_ver_cmp(ver:version, fix:fixes[i], same_branch:TRUE, is_min_check:FALSE) < 0 &&
    openssl_ver_cmp(ver:version, fix:cutoffs[i], same_branch:TRUE, is_min_check:FALSE) >= 0
  )
  {
    fix = fixes[i];
    break;
  }
}

if (!isnull(fix))
{
  report = '\n' +
    '\n  SecurityCenter version         : ' + sc_ver +
    '\n  SecurityCenter OpenSSL version : ' + version +
    '\n  Fixed OpenSSL version          : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OpenSSL (within SecurityCenter)", version);
