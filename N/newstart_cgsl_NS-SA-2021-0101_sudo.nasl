#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0101. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154615);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2011-0008",
    "CVE-2011-0010",
    "CVE-2012-0809",
    "CVE-2012-2337",
    "CVE-2013-1775",
    "CVE-2013-1776",
    "CVE-2017-1000368",
    "CVE-2021-3156"
  );
  script_xref(name:"IAVA", value:"2013-A-0179-S");
  script_xref(name:"IAVA", value:"2017-A-0165-S");
  script_xref(name:"IAVA", value:"2021-A-0053");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/27");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : sudo Multiple Vulnerabilities (NS-SA-2021-0101)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has sudo packages installed that are affected by
multiple vulnerabilities:

  - A certain Fedora patch for parse.c in sudo before 1.7.4p5-1.fc14 on Fedora 14 does not properly interpret
    a system group (aka %group) in the sudoers file during authorization decisions for a user who belongs to
    that group, which allows local users to leverage an applicable sudoers file and gain root privileges via a
    sudo command. NOTE: this vulnerability exists because of a CVE-2009-0034 regression. (CVE-2011-0008)

  - check.c in sudo 1.7.x before 1.7.4p5, when a Runas group is configured, does not require a password for
    command execution that involves a gid change but no uid change, which allows local users to bypass an
    intended authentication requirement via the -g option to a sudo command. (CVE-2011-0010)

  - Format string vulnerability in the sudo_debug function in Sudo 1.8.0 through 1.8.3p1 allows local users to
    execute arbitrary code via format string sequences in the program name for sudo. (CVE-2012-0809)

  - sudo 1.6.x and 1.7.x before 1.7.9p1, and 1.8.x before 1.8.4p5, does not properly support configurations
    that use a netmask syntax, which allows local users to bypass intended command restrictions in
    opportunistic circumstances by executing a command on a host that has an IPv4 address. (CVE-2012-2337)

  - sudo 1.6.0 through 1.7.10p6 and sudo 1.8.0 through 1.8.6p6 allows local users or physically proximate
    attackers to bypass intended time restrictions and retain privileges without re-authenticating by setting
    the system clock and sudo user timestamp to the epoch. (CVE-2013-1775)

  - sudo 1.3.5 through 1.7.10 and 1.8.0 through 1.8.5, when the tty_tickets option is enabled, does not
    properly validate the controlling terminal device, which allows local users with sudo permissions to
    hijack the authorization of another terminal via vectors related to connecting to the standard input,
    output, and error file descriptors of another terminal. NOTE: this is one of three closely-related
    vulnerabilities that were originally assigned CVE-2013-1776, but they have been SPLIT because of different
    affected versions. (CVE-2013-1776)

  - Todd Miller's sudo version 1.8.20p1 and earlier is vulnerable to an input validation (embedded newlines)
    in the get_process_ttyname() function resulting in information disclosure and command execution.
    (CVE-2017-1000368)

  - Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which
    allows privilege escalation to root via sudoedit -s and a command-line argument that ends with a single
    backslash character. (CVE-2021-3156)

  - A heap-based buffer overflow was found in the way sudo parses command line arguments. This flaw is
    exploitable by any local user who can execute the sudo command without authentication. Successful
    exploitation of this flaw could lead to privilege escalation.  (CVE-2021-3156)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0101");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2011-0008");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2011-0010");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2012-0809");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2012-2337");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2013-1775");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2013-1776");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2017-1000368");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3156");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL sudo packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3156");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-1000368");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sudo Heap-Based Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sudo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sudo-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'sudo-1.8.23-10.el7_9.1.cgslv5_4.0.1.g35f1fa1',
    'sudo-debuginfo-1.8.23-10.el7_9.1.cgslv5_4.0.1.g35f1fa1',
    'sudo-devel-1.8.23-10.el7_9.1.cgslv5_4.0.1.g35f1fa1'
  ],
  'CGSL MAIN 5.04': [
    'sudo-1.8.23-10.el7_9.1.cgslv5_4.0.1.g35f1fa1',
    'sudo-debuginfo-1.8.23-10.el7_9.1.cgslv5_4.0.1.g35f1fa1',
    'sudo-devel-1.8.23-10.el7_9.1.cgslv5_4.0.1.g35f1fa1'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'sudo');
}
