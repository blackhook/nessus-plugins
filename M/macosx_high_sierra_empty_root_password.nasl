#TRUSTED 51facbd69b41dffb76c2f4bc5de9d1548a952ebd06c9b25ae34b543a41f43ac4d854c9e95124705a7de86aa36a036069ec3da7ac5dab1122a591e00a9ad32d72599eddc251875aa5962bcb331600a5b8a487125514ce690f084636bb0cf9e73d510c442521e1de11da8d93e66ec6879b70d93395ed962b64958ede372c5de7b862b79efada31385a322f7c999c31385ba50796d369409914c03a4776f0a54d739b121a9cbc37715cd157980ad56b85804bd452ab13f89a4c4d48550f284336dbe26bb06f2e4d346bda160d208d233bf47dfe262ae23b44e6132c623ed0cdfc124880ca3dd3f0cf789902bf7fba0ea1d5cf898dd3e453a771badc7e9c43ab55228c473ad8af2183ad04b5c4f12aaff7d0e24e158f5cda31c6ba3a964770a50adcdc077d039ff889b62e18ffa3ab831ec90a51e00e43a155c0d97bc820dc6d37fc163a8b120e8956f2d82c11220883eaf90bdfb49803ec0f7884da3f6449cdaf6daf7875fc09fe4f95108e58b19719a8e96d37c30da5a41c38cfb1f662408615a31a1a56ac349392d65fe881698b6e52b392a43807d4e2fb5a603e45f4636b0b45404ea6733487f4a782e7218243ad5a478f5e83770c3b987ccbda67141a4083f61606e38d9e6a4b135ad176989c3cec6610ed79283a20ac5dbea5154b2c35c2a0da59d2ae5241e163a2bd3eadef73376ddc504ad1ed8810377cbac194fcef3d6c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104814);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2017-13872");
  script_bugtraq_id(101981);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-11-29-1");

  script_name(english:"MacOS 10.13 root Authentication Bypass (Security Update 2017-001)");
  script_summary(english:"Checks for the presence of Security Update 2017-001.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of MacOS that is affected by
a root authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of MacOS 10.13 or 10.13.1 that
is missing a security update. It is, therefore, affected by a root
authentication bypass vulnerability. A local attacker or a remote
attacker with credentials for a standard user account has the ability
to blank out the root account password. This can allow an attacker to
escalate privileges to root and execute commands and read files as a
system administrator.");
  # https://objective-see.com/blog/blog_0x24.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2cf4b55a");
  # https://twitter.com/lemiorhan/status/935578694541770752
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ff9ff45");
  # https://www.theregister.co.uk/2017/11/28/root_access_bypass_macos_high_sierra/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e5890f3");
  # https://www.theverge.com/2017/11/28/16711782/apple-macos-high-sierra-critical-password-security-flaw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f367aab4");
  # https://support.apple.com/en-us/HT204012
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9f9bbc3");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208315");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2017-001 or later. Alternatively, enable the
root account and set a strong root account password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13872");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X Root Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item_or_exit("Host/MacOSX/Version");

if (!preg(pattern:"Mac OS X 10\.13(\.[0-1]|[^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.13 / 10.13.1");

patch = "2017-001";
ver = UNKNOWN_VER;

cmd = "what /usr/libexec/opendirectoryd";
result = exec_cmd(cmd:cmd);
matches = pregmatch(pattern:"PROJECT:opendirectoryd-([0-9.]*)", string:result);
if (!isnull(matches) && !isnull(matches[1]))
  ver = matches[1];

if (preg(pattern:"Mac OS X 10\.13\.1([^0-9]|$)", string:os)) # 10.13.1
  fix = "483.20.7";
else # 10.13 / 10.13.0
  fix = "483.1.5";

if (ver == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER, "opendirectoryd");

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  report = '\n  Missing security update : ' + patch +
           '\n  opendirectoryd version  : ' + ver +
           '\n  Fixed version           : ' + fix +
           '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "opendirectoryd", ver);
