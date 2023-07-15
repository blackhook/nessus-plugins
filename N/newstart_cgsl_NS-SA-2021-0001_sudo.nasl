#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0001. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147406);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2010-0426",
    "CVE-2010-2956",
    "CVE-2017-1000368",
    "CVE-2019-14287",
    "CVE-2019-18634",
    "CVE-2021-3156"
  );
  script_bugtraq_id(38362, 43019, 98838);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/27");

  script_name(english:"NewStart CGSL MAIN 4.06 : sudo Multiple Vulnerabilities (NS-SA-2021-0001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.06, has sudo packages installed that are affected by multiple
vulnerabilities:

  - In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer
    overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS;
    however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an
    administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.
    (CVE-2019-18634)

  - In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy
    blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user
    ID. For example, this allows bypass of !root configuration, and USER= logging, for a sudo -u
    \#$((0xffffffff)) command. (CVE-2019-14287)

  - sudo 1.6.x before 1.6.9p21 and 1.7.x before 1.7.2p4, when a pseudo-command is enabled, permits a match
    between the name of the pseudo-command and the name of an executable file in an arbitrary directory, which
    allows local users to gain privileges via a crafted executable file, as demonstrated by a file named
    sudoedit in a user's home directory. (CVE-2010-0426)

  - Sudo 1.7.0 through 1.7.4p3, when a Runas group is configured, does not properly handle use of the -u
    option in conjunction with the -g option, which allows local users to gain privileges via a command line
    containing a -u root sequence. (CVE-2010-2956)

  - Todd Miller's sudo version 1.8.20p1 and earlier is vulnerable to an input validation (embedded newlines)
    in the get_process_ttyname() function resulting in information disclosure and command execution.
    (CVE-2017-1000368)

  - Sudo before 1.9.5p2 has a Heap-based Buffer Overflow, allowing privilege escalation to root via sudoedit
    -s and a command-line argument that ends with a single backslash character. (CVE-2021-3156)

  - A heap-based buffer overflow was found in the way sudo parses command line arguments. This flaw is
    exploitable by any local user who can execute the sudo command without authentication. Successful
    exploitation of this flaw could lead to privilege escalation.  (CVE-2021-3156)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0001");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL sudo packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14287");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sudo Heap-Based Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 4.06")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.06');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 4.06': [
    'sudo-1.8.6p3-29.el6_10.4.cgslv4_6.0.1.g1bc9918',
    'sudo-devel-1.8.6p3-29.el6_10.4.cgslv4_6.0.1.g1bc9918'
  ]
};
pkg_list = pkgs[release];

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'sudo');
}
