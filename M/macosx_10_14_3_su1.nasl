#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(122508);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-6223", "CVE-2019-7286", "CVE-2019-7288");
  script_bugtraq_id(106951, 106962);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-02-07-2");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"macOS 10.14.3 Supplemental Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update that fixes
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS 10.14.3 that is missing
the macOS 10.14.3 Supplemental Update.  This update fixes the
following vulnerabilities :

  - An unspecified flaw exists related to handling Group
    FaceTime calls that allows an attacker to cause a call
    recipient to unintentionally answer. (CVE-2019-6223)

  - An input-validation flaw exists related to the
    Foundation component that allows memory corruption and
    privilege escalation. (CVE-2019-7286)

  - An unspecified flaw exists related to Live Photos in
    FaceTime having unspecified impact. (CVE-2019-7288)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT209521");
  # https://lists.apple.com/archives/security-announce/2019/Feb/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e5ff1d7");
  script_set_attribute(attribute:"solution", value:
"Install the macOS 10.14.3 Supplemental Update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7288");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!preg(pattern:"Mac OS X 10\.14\.3([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "macOS 10.14.3");


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
  build !~ "^18D[0-9]+$"
) exit(1, "Failed to extract the ProductBuildVersion from '"+plist+"'.");


if (build =~ "^18D([0-9]|[0-9][0-9]|10[0-8])$")
{
  report = '\n  Product version                 : ' + os +
           '\n  Installed product build version : ' + build +
           '\n  Fixed product build version     : 18D109' +
           '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else exit(0, "The host has product build version "+build+" and is not affected.");
