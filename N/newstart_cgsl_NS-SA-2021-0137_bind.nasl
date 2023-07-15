#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0137. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154482);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2020-8616", "CVE-2020-8617");
  script_xref(name:"IAVA", value:"2020-A-0217-S");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : bind Multiple Vulnerabilities (NS-SA-2021-0137)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has bind packages installed that are affected by
multiple vulnerabilities:

  - A malicious actor who intentionally exploits this lack of effective limitation on the number of fetches
    performed when processing referrals can, through the use of specially crafted referrals, cause a recursing
    server to issue a very large number of fetches in an attempt to process the referral. This has at least
    two potential effects: The performance of the recursing server can potentially be degraded by the
    additional work required to perform these fetches, and The attacker can exploit this behavior to use the
    recursing server as a reflector in a reflection attack with a high amplification factor. (CVE-2020-8616)

  - Using a specially-crafted message, an attacker may potentially cause a BIND server to reach an
    inconsistent state if the attacker knows (or successfully guesses) the name of a TSIG key used by the
    server. Since BIND, by default, configures a local session key even on servers whose configuration does
    not otherwise make use of it, almost all current BIND servers are vulnerable. In releases of BIND dating
    from March 2018 and after, an assertion check in tsig.c detects this inconsistent state and deliberately
    exits. Prior to the introduction of the check the server would continue operating in an inconsistent
    state, with potentially harmful results. (CVE-2020-8617)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0137");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-8616");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-8617");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL bind packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8617");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-8616");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'bind-9.11.4-16.P2.el7_8.6',
    'bind-chroot-9.11.4-16.P2.el7_8.6',
    'bind-debuginfo-9.11.4-16.P2.el7_8.6',
    'bind-devel-9.11.4-16.P2.el7_8.6',
    'bind-export-devel-9.11.4-16.P2.el7_8.6',
    'bind-export-libs-9.11.4-16.P2.el7_8.6',
    'bind-libs-9.11.4-16.P2.el7_8.6',
    'bind-libs-lite-9.11.4-16.P2.el7_8.6',
    'bind-license-9.11.4-16.P2.el7_8.6',
    'bind-lite-devel-9.11.4-16.P2.el7_8.6',
    'bind-pkcs11-9.11.4-16.P2.el7_8.6',
    'bind-pkcs11-devel-9.11.4-16.P2.el7_8.6',
    'bind-pkcs11-libs-9.11.4-16.P2.el7_8.6',
    'bind-pkcs11-utils-9.11.4-16.P2.el7_8.6',
    'bind-sdb-9.11.4-16.P2.el7_8.6',
    'bind-sdb-chroot-9.11.4-16.P2.el7_8.6',
    'bind-utils-9.11.4-16.P2.el7_8.6'
  ],
  'CGSL MAIN 5.05': [
    'bind-9.11.4-16.P2.el7_8.6',
    'bind-chroot-9.11.4-16.P2.el7_8.6',
    'bind-debuginfo-9.11.4-16.P2.el7_8.6',
    'bind-devel-9.11.4-16.P2.el7_8.6',
    'bind-export-devel-9.11.4-16.P2.el7_8.6',
    'bind-export-libs-9.11.4-16.P2.el7_8.6',
    'bind-libs-9.11.4-16.P2.el7_8.6',
    'bind-libs-lite-9.11.4-16.P2.el7_8.6',
    'bind-license-9.11.4-16.P2.el7_8.6',
    'bind-lite-devel-9.11.4-16.P2.el7_8.6',
    'bind-pkcs11-9.11.4-16.P2.el7_8.6',
    'bind-pkcs11-devel-9.11.4-16.P2.el7_8.6',
    'bind-pkcs11-libs-9.11.4-16.P2.el7_8.6',
    'bind-pkcs11-utils-9.11.4-16.P2.el7_8.6',
    'bind-sdb-9.11.4-16.P2.el7_8.6',
    'bind-sdb-chroot-9.11.4-16.P2.el7_8.6',
    'bind-utils-9.11.4-16.P2.el7_8.6'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind');
}
