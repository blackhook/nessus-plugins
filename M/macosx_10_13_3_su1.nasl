#TRUSTED 8fd6c7565ae6ad5da750e136f56d5529ecb6abf7c71d7914a6d658c3eb1e2ee951e03d9300f51184d27fe29986405872740988549a0bf11de96c3ff4eea76cec841ba709856df715d0271a804cf3ed3bf411fd2831f64c76ef83f62ed02e4bd7990da2e417e1959b71bda5e66c59c78c745513a5a0106d05483b651daa47ee911e5077db15f0ed7d67fe556f831797a67040f44285822bfb223d1700d98dbf56e8788108087a256f0cd2ffe4e19144201313f3b2c860558039ab8409d27b30647a7fee7feac5791355378aa97d6c25b307a9e26f0e54727f54617b2abf50bc3cc5f292786b1ad4356b2924631f075a0a568d16254be5e19c6f17b20987d5eb9a5e86c1e2480e2e61bde4d9969f2a917ba639faf8f2c85df9280213412553f1b67b9464d73ddc79413ae9ac70680b820aa5c8371930f022f1dff1135de436a70100586aa545c0c94fbc747f6550295dafcf5d63ad0ba6a6807e17b39d3694a6f0b61c77b98139141fe15728d5133ca281c2f33c49b3bd360fe9afe48c163ffa1681afb0ef835914e885d61ffc3d44933df72b9935c062c26c380ed5b9110db4344feec1c5b34369577cc2804e71a985a8d0d7ad00180962e97333e6daf4afe8426482706904fcb2133f3b19cfc1cea0c98f9a7067b7f373dd6829e24494be7bdfba39b482720c3c7e6b71ec67eab97cf0588f84df1baf582cfd1690a6244691ac
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(107071);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2018-4124");
  script_bugtraq_id(103066);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2018-02-19-2");

  script_name(english:"macOS 10.13.3 Supplemental Update");
  script_summary(english:"Check the version of Mac OS X / macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update that fixes an
input-validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS 10.13.3 that is missing
the macOS 10.13.3 Supplemental Update.  This update fixes an input-
validation flaw, which allows an attacker to cause memory corruption
leading to application crashes and potentially to arbitrary code
execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208535");
  # https://lists.apple.com/archives/security-announce/2018/Feb/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?866048f5");
  script_set_attribute(attribute:"solution", value:
"Install the macOS 10.13.3 Supplemental Update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4124");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X / macOS");
if (!preg(pattern:"Mac OS X 10\.13\.3([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "macOS 10.13.3");


# Get the product build version.
plist = "/System/Library/CoreServices/SystemVersion.plist";
cmd =
  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 ProductBuildVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
build = exec_cmd(cmd:cmd);
if (
  !strlen(build) ||
  build !~ "^17D[0-9]+$"
) exit(1, "Failed to extract the ProductBuildVersion from '"+plist+"'.");


if (build =~ "^17D([0-9]|[0-9][0-9]|10[01])$")
{
  report = '\n  Product version                 : ' + os +
           '\n  Installed product build version : ' + build +
           '\n  Fixed product build version     : 17D102' +
           '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else exit(0, "The host has product build version "+build+" and is not affected.");
