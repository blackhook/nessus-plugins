##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0055. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160827);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2019-3842",
    "CVE-2019-20386",
    "CVE-2020-13776",
    "CVE-2021-33910"
  );
  script_xref(name:"IAVA", value:"2021-A-0350");

  script_name(english:"NewStart CGSL MAIN 6.02 : systemd Multiple Vulnerabilities (NS-SA-2022-0055)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has systemd packages installed that are affected by multiple
vulnerabilities:

  - An issue was discovered in button_open in login/logind-button.c in systemd before 243. When executing the
    udevadm trigger command, a memory leak may occur. (CVE-2019-20386)

  - In systemd before v242-rc4, it was discovered that pam_systemd does not properly sanitize the environment
    before using the XDG_SEAT variable. It is possible for an attacker, in some particular configurations, to
    set a XDG_SEAT environment variable which allows for commands to be checked against polkit policies using
    the allow_active element rather than allow_any. (CVE-2019-3842)

  - systemd through v245 mishandles numerical usernames such as ones composed of decimal digits or 0x followed
    by hex digits, as demonstrated by use of root privileges when privileges of the 0x0 user account were
    intended. NOTE: this issue exists because of an incomplete fix for CVE-2017-1000082. (CVE-2020-13776)

  - basic/unit-name.c in systemd prior to 246.15, 247.8, 248.5, and 249.1 has a Memory Allocation with an
    Excessive Size Value (involving strdupa and alloca for a pathname controlled by a local attacker) that
    results in an operating system crash. (CVE-2021-33910)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0055");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-20386");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-3842");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-13776");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-33910");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL systemd packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13776");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-3842");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-container-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-journal-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-journal-remote-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-pam-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'systemd-239-45.el8_4.2.cgslv6_2.9.g6080158',
    'systemd-container-239-45.el8_4.2.cgslv6_2.9.g6080158',
    'systemd-container-debuginfo-239-45.el8_4.2.cgslv6_2.9.g6080158',
    'systemd-debuginfo-239-45.el8_4.2.cgslv6_2.9.g6080158',
    'systemd-debugsource-239-45.el8_4.2.cgslv6_2.9.g6080158',
    'systemd-devel-239-45.el8_4.2.cgslv6_2.9.g6080158',
    'systemd-journal-remote-239-45.el8_4.2.cgslv6_2.9.g6080158',
    'systemd-journal-remote-debuginfo-239-45.el8_4.2.cgslv6_2.9.g6080158',
    'systemd-libs-239-45.el8_4.2.cgslv6_2.9.g6080158',
    'systemd-libs-debuginfo-239-45.el8_4.2.cgslv6_2.9.g6080158',
    'systemd-pam-239-45.el8_4.2.cgslv6_2.9.g6080158',
    'systemd-pam-debuginfo-239-45.el8_4.2.cgslv6_2.9.g6080158',
    'systemd-tests-239-45.el8_4.2.cgslv6_2.9.g6080158',
    'systemd-tests-debuginfo-239-45.el8_4.2.cgslv6_2.9.g6080158',
    'systemd-udev-239-45.el8_4.2.cgslv6_2.9.g6080158',
    'systemd-udev-debuginfo-239-45.el8_4.2.cgslv6_2.9.g6080158'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'systemd');
}
