#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0153. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154490);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id("CVE-2020-8622", "CVE-2020-8623", "CVE-2020-8624");
  script_xref(name:"IAVA", value:"2020-A-0385-S");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : bind Multiple Vulnerabilities (NS-SA-2021-0153)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has bind packages installed that are affected by
multiple vulnerabilities:

  - In BIND 9.0.0 -> 9.11.21, 9.12.0 -> 9.16.5, 9.17.0 -> 9.17.3, also affects 9.9.3-S1 -> 9.11.21-S1 of the
    BIND 9 Supported Preview Edition, An attacker on the network path for a TSIG-signed request, or operating
    the server receiving the TSIG-signed request, could send a truncated response to that request, triggering
    an assertion failure, causing the server to exit. Alternately, an off-path attacker would have to
    correctly guess when a TSIG-signed request was sent, along with other characteristics of the packet and
    message, and spoof a truncated response to trigger an assertion failure, causing the server to exit.
    (CVE-2020-8622)

  - In BIND 9.10.0 -> 9.11.21, 9.12.0 -> 9.16.5, 9.17.0 -> 9.17.3, also affects 9.10.5-S1 -> 9.11.21-S1 of the
    BIND 9 Supported Preview Edition, An attacker that can reach a vulnerable system with a specially crafted
    query packet can trigger a crash. To be vulnerable, the system must: * be running BIND that was built with
    --enable-native-pkcs11 * be signing one or more zones with an RSA key * be able to receive queries from
    a possible attacker (CVE-2020-8623)

  - In BIND 9.9.12 -> 9.9.13, 9.10.7 -> 9.10.8, 9.11.3 -> 9.11.21, 9.12.1 -> 9.16.5, 9.17.0 -> 9.17.3, also
    affects 9.9.12-S1 -> 9.9.13-S1, 9.11.3-S1 -> 9.11.21-S1 of the BIND 9 Supported Preview Edition, An
    attacker who has been granted privileges to change a specific subset of the zone's content could abuse
    these unintended additional privileges to update other contents of the zone. (CVE-2020-8624)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0153");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-8622");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-8623");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-8624");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL bind packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bind-chroot");
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

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'bind-9.11.4-26.P2.el7_9.2',
    'bind-chroot-9.11.4-26.P2.el7_9.2',
    'bind-devel-9.11.4-26.P2.el7_9.2',
    'bind-export-devel-9.11.4-26.P2.el7_9.2',
    'bind-export-libs-9.11.4-26.P2.el7_9.2',
    'bind-libs-9.11.4-26.P2.el7_9.2',
    'bind-libs-lite-9.11.4-26.P2.el7_9.2',
    'bind-license-9.11.4-26.P2.el7_9.2',
    'bind-lite-devel-9.11.4-26.P2.el7_9.2',
    'bind-pkcs11-9.11.4-26.P2.el7_9.2',
    'bind-pkcs11-devel-9.11.4-26.P2.el7_9.2',
    'bind-pkcs11-libs-9.11.4-26.P2.el7_9.2',
    'bind-pkcs11-utils-9.11.4-26.P2.el7_9.2',
    'bind-sdb-9.11.4-26.P2.el7_9.2',
    'bind-sdb-chroot-9.11.4-26.P2.el7_9.2',
    'bind-utils-9.11.4-26.P2.el7_9.2'
  ],
  'CGSL MAIN 5.05': [
    'bind-9.11.4-26.P2.el7_9.2',
    'bind-chroot-9.11.4-26.P2.el7_9.2',
    'bind-devel-9.11.4-26.P2.el7_9.2',
    'bind-export-devel-9.11.4-26.P2.el7_9.2',
    'bind-export-libs-9.11.4-26.P2.el7_9.2',
    'bind-libs-9.11.4-26.P2.el7_9.2',
    'bind-libs-lite-9.11.4-26.P2.el7_9.2',
    'bind-license-9.11.4-26.P2.el7_9.2',
    'bind-lite-devel-9.11.4-26.P2.el7_9.2',
    'bind-pkcs11-9.11.4-26.P2.el7_9.2',
    'bind-pkcs11-devel-9.11.4-26.P2.el7_9.2',
    'bind-pkcs11-libs-9.11.4-26.P2.el7_9.2',
    'bind-pkcs11-utils-9.11.4-26.P2.el7_9.2',
    'bind-sdb-9.11.4-26.P2.el7_9.2',
    'bind-sdb-chroot-9.11.4-26.P2.el7_9.2',
    'bind-utils-9.11.4-26.P2.el7_9.2'
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
