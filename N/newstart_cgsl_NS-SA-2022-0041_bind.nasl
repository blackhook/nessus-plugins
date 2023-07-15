##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0041. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160871);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2021-25214");
  script_xref(name:"IAVA", value:"2021-A-0206-S");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : bind Vulnerability (NS-SA-2022-0041)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has bind packages installed that are affected by a
vulnerability:

  - In BIND 9.8.5 -> 9.8.8, 9.9.3 -> 9.11.29, 9.12.0 -> 9.16.13, and versions BIND 9.9.3-S1 -> 9.11.29-S1 and
    9.16.8-S1 -> 9.16.13-S1 of BIND 9 Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.11
    of the BIND 9.17 development branch, when a vulnerable version of named receives a malformed IXFR
    triggering the flaw described above, the named process will terminate due to a failed assertion the next
    time the transferred secondary zone is refreshed. (CVE-2021-25214)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0041");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-25214");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL bind packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25214");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

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

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

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
    'bind-9.11.4-26.P2.el7_9.7',
    'bind-chroot-9.11.4-26.P2.el7_9.7',
    'bind-debuginfo-9.11.4-26.P2.el7_9.7',
    'bind-devel-9.11.4-26.P2.el7_9.7',
    'bind-export-devel-9.11.4-26.P2.el7_9.7',
    'bind-export-libs-9.11.4-26.P2.el7_9.7',
    'bind-libs-9.11.4-26.P2.el7_9.7',
    'bind-libs-lite-9.11.4-26.P2.el7_9.7',
    'bind-license-9.11.4-26.P2.el7_9.7',
    'bind-lite-devel-9.11.4-26.P2.el7_9.7',
    'bind-pkcs11-9.11.4-26.P2.el7_9.7',
    'bind-pkcs11-devel-9.11.4-26.P2.el7_9.7',
    'bind-pkcs11-libs-9.11.4-26.P2.el7_9.7',
    'bind-pkcs11-utils-9.11.4-26.P2.el7_9.7',
    'bind-sdb-9.11.4-26.P2.el7_9.7',
    'bind-sdb-chroot-9.11.4-26.P2.el7_9.7',
    'bind-utils-9.11.4-26.P2.el7_9.7'
  ],
  'CGSL MAIN 5.05': [
    'bind-9.11.4-26.P2.el7_9.7',
    'bind-chroot-9.11.4-26.P2.el7_9.7',
    'bind-debuginfo-9.11.4-26.P2.el7_9.7',
    'bind-devel-9.11.4-26.P2.el7_9.7',
    'bind-export-devel-9.11.4-26.P2.el7_9.7',
    'bind-export-libs-9.11.4-26.P2.el7_9.7',
    'bind-libs-9.11.4-26.P2.el7_9.7',
    'bind-libs-lite-9.11.4-26.P2.el7_9.7',
    'bind-license-9.11.4-26.P2.el7_9.7',
    'bind-lite-devel-9.11.4-26.P2.el7_9.7',
    'bind-pkcs11-9.11.4-26.P2.el7_9.7',
    'bind-pkcs11-devel-9.11.4-26.P2.el7_9.7',
    'bind-pkcs11-libs-9.11.4-26.P2.el7_9.7',
    'bind-pkcs11-utils-9.11.4-26.P2.el7_9.7',
    'bind-sdb-9.11.4-26.P2.el7_9.7',
    'bind-sdb-chroot-9.11.4-26.P2.el7_9.7',
    'bind-utils-9.11.4-26.P2.el7_9.7'
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
