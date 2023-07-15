#TRUSTED 1c4a7e45d3f234a30f81cd7683f404b11055deb8a53529d767f4bd886ce1d5b9af76a1a57b4f1e65160cc909b83ab00f7544831d60dd985831351690257fe1093ef97db6baaadbeba93d9dda882e7f68fa0fe9d3c1ef7923d4eac0689362a56829246f5abb43f12e752dc703ce064903c3201949e7f640bd058431cace13130e05d4df7ce936b15a18bda9e3707e5fa44370ed05e36f43c746ea126aeb8f73e160b5a09966ce7a7bbdc2971b1c57fce74c2f8bc6144662066fabb7fd195febb28b95f4197cfd3007eeba3e62c5c0ce883f2951144b4f18c355af8871e651407949ed4eedbeee5b34c08f7e80995e292ac98c9ce7c2330f7a234a21f737682e6746fe007e6594826229a247b5aa31363317f975cf4e165d9b0dfb8f3f6ad5e389693320438ca265f5f88d3d2bc1c801be2ca714325018d80f36ed7f46ff4d0fe2ce2a758a8a11084ee10ae9553cba04cf0c1370f852b628456fa6ca8639d13247b8c3c6b4655ecfc30f689175c17f01d8af494977b05c6faeef075748f18544a3ffa17dbbd27ba650d34e3ed11b2c3615ee1d07f0762d116c45084d41f850313bdcc4d6c7f9cb6944a3eaf7e054fe1bc959439c7d50eec1045201f01f636351c53cd864ffceab43326ef257d0e1c0d1d3d737fc0a4f630c241d15735f1b76edb2d390d474a655cdb1bd0b1e973b326ffaef3e782aa5b34678f066a3d1837fffd6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(118155);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/15");

 script_cve_id("CVE-2018-10933");
 script_xref(name:"IAVA", value:"2018-A-0347-S");

 script_name(english:"libssh 0.6.x / 0.7.x < 0.7.6 / 0.8.x < 0.8.4 Authentication Bypass (Remote Version Check)");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to an authentication bypass." );
 script_set_attribute(attribute:"description", value:
"According to its banner version, the remote libssh based server is
vulnerable to an authentication bypass.  An attacker can bypass
authentication by presenting a SSH2_MSG_USERAUTH_SUCCESS message in
place of the SSH2_MSG_USERAUTH_REQUEST method that normally would
initiate authentication.

Note that Nessus did not actually test for the flaw but instead has
relied on the version in the libssh banner so this may be a false
positive.");
 #https://www.libssh.org/2018/10/16/libssh-0-8-4-and-0-7-6-security-and-bugfix-release/
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?6f6b157e");
 script_set_attribute(attribute:"solution", value:
"Upgrade to libssh 0.7.6 / 0.8.4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10933");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2018/10/16");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_summary(english:"Check libssh banner");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Misc.");
 script_dependencies("find_service1.nasl");
 script_require_ports("Services/ssh", 22);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("vcf.inc");
include("ssh_lib.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = 'libssh server';

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if(!soc)
  audit(AUDIT_SOCK_FAIL, port);

session = new("sshlib::session");
session.set_socket(soc);

session.cur_state.set("SOC_OPENED");

banner= '';
var tmp_chr = '';

# initial connection may be slow on some devices
tmp_chr = session.sshrecv(timeout:30, length:1);
var i = 0;
while(tmp_chr != '' && !isnull(tmp_chr) && tmp_chr =~ '[a-zA-Z0-9._-]' && session.cur_state.val == "SOC_OPENED" && i < 512)
{
  banner += tmp_chr;
  tmp_chr = session.sshrecv(timeout:5, length:1);
  i++;
}

if(!banner)
{
  session.close_socket(error:"No remote version received");
  audit(AUDIT_NO_BANNER, port);
}
if(banner!~ "^SSH-2.0-libssh[_-]")
  audit(AUDIT_NOT_LISTEN, app_name, port);

version = ereg_replace(pattern:"^SSH-2.0-libssh[_-]([0-9.]+).*$", replace:"\1", string:banner);

session.close_socket();

constraints = [{"min_version": "0.6", "fixed_version": "0.7.6"},
               {"min_version": "0.8", "fixed_version": "0.8.4"}];

ver_match = vcf::check_version(version:vcf::parse_version(version), constraints: constraints);
if(!isnull(ver_match))
{
  report =
  '\n  Product       : ' + app_name + 
  '\n  Version       : ' + version +
  '\n  Fixed version : ' + ver_match["fixed_version"] +
  '\n';

  security_report_v4(port: port, severity:SECURITY_WARNING, extra:report);
}
else
{
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
}
