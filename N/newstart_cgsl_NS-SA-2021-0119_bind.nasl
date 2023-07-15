#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0119. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154595);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/28");

  script_cve_id("CVE-2020-8625");
  script_xref(name:"IAVA", value:"2021-A-0101-S");

  script_name(english:"NewStart CGSL MAIN 6.02 : bind Vulnerability (NS-SA-2021-0119)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has bind packages installed that are affected by a
vulnerability:

  - BIND servers are vulnerable if they are running an affected version and are configured to use GSS-TSIG
    features. In a configuration which uses BIND's default settings the vulnerable code path is not exposed,
    but a server can be rendered vulnerable by explicitly setting valid values for the tkey-gssapi-keytab or
    tkey-gssapi-credentialconfiguration options. Although the default configuration is not vulnerable, GSS-
    TSIG is frequently used in networks where BIND is integrated with Samba, as well as in mixed-server
    environments that combine BIND servers with Active Directory domain controllers. The most likely outcome
    of a successful exploitation of the vulnerability is a crash of the named process. However, remote code
    execution, while unproven, is theoretically possible. Affects: BIND 9.5.0 -> 9.11.27, 9.12.0 -> 9.16.11,
    and versions BIND 9.11.3-S1 -> 9.11.27-S1 and 9.16.8-S1 -> 9.16.11-S1 of BIND Supported Preview Edition.
    Also release versions 9.17.0 -> 9.17.1 of the BIND 9.17 development branch (CVE-2020-8625)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0119");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-8625");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL bind packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8625");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-export-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-libs-lite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-pkcs11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-pkcs11-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-pkcs11-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-sdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
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

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'bind-9.11.20-5.el8_3.1',
    'bind-chroot-9.11.20-5.el8_3.1',
    'bind-debuginfo-9.11.20-5.el8_3.1',
    'bind-debugsource-9.11.20-5.el8_3.1',
    'bind-devel-9.11.20-5.el8_3.1',
    'bind-export-devel-9.11.20-5.el8_3.1',
    'bind-export-libs-9.11.20-5.el8_3.1',
    'bind-export-libs-debuginfo-9.11.20-5.el8_3.1',
    'bind-libs-9.11.20-5.el8_3.1',
    'bind-libs-debuginfo-9.11.20-5.el8_3.1',
    'bind-libs-lite-9.11.20-5.el8_3.1',
    'bind-libs-lite-debuginfo-9.11.20-5.el8_3.1',
    'bind-license-9.11.20-5.el8_3.1',
    'bind-lite-devel-9.11.20-5.el8_3.1',
    'bind-pkcs11-9.11.20-5.el8_3.1',
    'bind-pkcs11-debuginfo-9.11.20-5.el8_3.1',
    'bind-pkcs11-devel-9.11.20-5.el8_3.1',
    'bind-pkcs11-libs-9.11.20-5.el8_3.1',
    'bind-pkcs11-libs-debuginfo-9.11.20-5.el8_3.1',
    'bind-pkcs11-utils-9.11.20-5.el8_3.1',
    'bind-pkcs11-utils-debuginfo-9.11.20-5.el8_3.1',
    'bind-sdb-9.11.20-5.el8_3.1',
    'bind-sdb-chroot-9.11.20-5.el8_3.1',
    'bind-sdb-debuginfo-9.11.20-5.el8_3.1',
    'bind-utils-9.11.20-5.el8_3.1',
    'bind-utils-debuginfo-9.11.20-5.el8_3.1',
    'python3-bind-9.11.20-5.el8_3.1'
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
