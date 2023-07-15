#TRUSTED 48d32e022c07325d4f4bc7b1b1ec1c4bca2ab3c4605aabce83bda641c8b78be466e845e0bce0b727db0ed08bb5bf71ec2df6455abd6b3a1e562b474e1455278f49ecfc7239da74e97edc60ec8b2427cf3a287a494b3fc260c867ca16e94b4e81ae5b0e030253d1d726f14d1b5135fe0b63c4bf66897de91ab4e2638d285a49f63122b0aa8deeff78437440860466683197c3fc7b2dc012cd662021e1759f51f4b4771b8c7103adc1e02f92ccab1e7178c8fbc2189e70d01948e11f2e6fea6f71ef9535f630f42f20e502b53527122cacf57f13fe1ff82d302916a4609cfae6c932214d2408e7df1e663f77ef849fd496f6f5761e624d496953bb11afa323f6ec7fc8430384d7d4e9e0fe9ff2e14b857bd24500c55c4f0ca5a207d6836717141dcb2433fc208947d2429d8924147e6fa765f38f3b29e09968cd826ae5e3f6d4d6ed994708c8a3886437c2af2ffe7237f74ab15374a5d46775632fe00a432ed2a91ac6c40dd066071df912a422a01fdf1e6c10a28af576b3b6653da44ec4fddf930ad18e5580f807fe000db4406e2a18e5f959b786b016340d741fbf94e1731fbb533f09080d6014a4f91fe796422394146fde878922cc383aa684a56eabd6511715b3a4239db7f47883606f4f4818cf47c0dae0d9242329e5ab475d189796e0bd25e704ccdcdca4244582fc75823c938d98971851f138c124f782755ba5470479
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104052);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2016-6814");
  script_bugtraq_id(95429);

  script_name(english:"Oracle Enterprise Manager Ops Center Remote Code Execution (October 2017 CPU)");
  script_summary(english:"Checks the version of a library.");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Ops Center installed on
the remote host is missing a security patch. It is, therefore,
affected by a remote code execution vulnerability. Refer to the
October 2017 CPU for details on this vulnerability.");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e07fa0e");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2017 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6814");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("audit.inc");
include("ssh_func.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

patch = "26974609";

installed_cmd = "bash -c 'if [ -f /opt/sun/xvmoc/bin/satadm ]; then echo 1; else echo 0; fi'";

ret = ssh_open_connection();

if(!ret) exit(0);

buf = ssh_cmd(cmd:installed_cmd);

if("1" >!< buf)
{
  ssh_close_connection();
  audit(AUDIT_NOT_INST, "Oracle Enterprise Manager Ops Center");
}

lib_ver_cmd = "unzip -q -c /opt/sun/n1gc/lib/commons-fileupload.jar META-INF/MANIFEST.MF | grep Implementation-Version";

buf = ssh_cmd(cmd:lib_ver_cmd);
ssh_close_connection();

if("Implementation-Version" >!< buf) audit(AUDIT_VER_FAIL, "commons-fileupload.jar");

version = pregmatch(pattern:"Implementation-Version:\s+([0-9.]+)", string:buf);

if(isnull(version) || isnull(version[1])) audit(AUDIT_VER_FAIL, "commons-fileupload.jar");

version = version[1];

report = 'The install of Oracle Enterprise Manager Ops Center is missing the\n';
report += 'following patch :\n\n  ' + patch + '\n\nThis was determined by';
report += ' the version of the commons-fileupload.jar library.\n\n';
report += '  Patched version : 1.3.2\n';
report += '  Installed version : ' + version + '\n';

if(ver_compare(ver:version, fix:"1.3.2") < 0)
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
else
  audit(AUDIT_INST_VER_NOT_VULN, "Oracle Enterprise Manager Ops Center");
