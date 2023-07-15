#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0118. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154582);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-7169", "CVE-2016-0634", "CVE-2016-7543");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");

  script_name(english:"NewStart CGSL MAIN 6.02 : bash Multiple Vulnerabilities (NS-SA-2021-0118)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has bash packages installed that are affected by multiple
vulnerabilities:

  - GNU Bash through 4.3 bash43-025 processes trailing strings after certain malformed function definitions in
    the values of environment variables, which allows remote attackers to write to files or possibly have
    unknown other impact via a crafted environment, as demonstrated by vectors involving the ForceCommand
    feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by
    unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege
    boundary from Bash execution. NOTE: this vulnerability exists because of an incomplete fix for
    CVE-2014-6271. (CVE-2014-7169)

  - The expansion of '\h' in the prompt string in bash 4.3 allows remote authenticated users to execute
    arbitrary code via shell metacharacters placed in 'hostname' of a machine. (CVE-2016-0634)

  - Bash before 4.4 allows local users to execute arbitrary commands with root privileges via crafted
    SHELLOPTS and PS4 environment variables. (CVE-2016-7543)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0118");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2014-7169");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2016-0634");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2016-7543");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL bash packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-7169");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-7543");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bash-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bash-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bash-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
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

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'bash-4.4.19-10.el8.cgslv6_2.0.1.g98f2d97',
    'bash-debuginfo-4.4.19-10.el8.cgslv6_2.0.1.g98f2d97',
    'bash-debugsource-4.4.19-10.el8.cgslv6_2.0.1.g98f2d97',
    'bash-devel-4.4.19-10.el8.cgslv6_2.0.1.g98f2d97',
    'bash-doc-4.4.19-10.el8.cgslv6_2.0.1.g98f2d97'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bash');
}
