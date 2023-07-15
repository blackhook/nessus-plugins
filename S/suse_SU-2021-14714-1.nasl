#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:14714-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150646);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/09");

  script_cve_id("CVE-2021-25214", "CVE-2021-25215", "CVE-2021-25216");
  script_xref(name:"SuSE", value:"SUSE-SU-2021:14714-1");
  script_xref(name:"IAVA", value:"2021-A-0206-S");

  script_name(english:"SUSE SLES11 Security Update : bind (SUSE-SU-2021:14714-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:14714-1 advisory.

  - In BIND 9.8.5 -> 9.8.8, 9.9.3 -> 9.11.29, 9.12.0 -> 9.16.13, and versions BIND 9.9.3-S1 -> 9.11.29-S1 and
    9.16.8-S1 -> 9.16.13-S1 of BIND 9 Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.11
    of the BIND 9.17 development branch, when a vulnerable version of named receives a malformed IXFR
    triggering the flaw described above, the named process will terminate due to a failed assertion the next
    time the transferred secondary zone is refreshed. (CVE-2021-25214)

  - In BIND 9.0.0 -> 9.11.29, 9.12.0 -> 9.16.13, and versions BIND 9.9.3-S1 -> 9.11.29-S1 and 9.16.8-S1 ->
    9.16.13-S1 of BIND Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.11 of the BIND
    9.17 development branch, when a vulnerable version of named receives a query for a record triggering the
    flaw described above, the named process will terminate due to a failed assertion check. The vulnerability
    affects all currently maintained BIND 9 branches (9.11, 9.11-S, 9.16, 9.16-S, 9.17) as well as all other
    versions of BIND 9. (CVE-2021-25215)

  - In BIND 9.5.0 -> 9.11.29, 9.12.0 -> 9.16.13, and versions BIND 9.11.3-S1 -> 9.11.29-S1 and 9.16.8-S1 ->
    9.16.13-S1 of BIND Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.1 of the BIND
    9.17 development branch, BIND servers are vulnerable if they are running an affected version and are
    configured to use GSS-TSIG features. In a configuration which uses BIND's default settings the vulnerable
    code path is not exposed, but a server can be rendered vulnerable by explicitly setting values for the
    tkey-gssapi-keytab or tkey-gssapi-credential configuration options. Although the default configuration is
    not vulnerable, GSS-TSIG is frequently used in networks where BIND is integrated with Samba, as well as in
    mixed-server environments that combine BIND servers with Active Directory domain controllers. For servers
    that meet these conditions, the ISC SPNEGO implementation is vulnerable to various attacks, depending on
    the CPU architecture for which BIND was built: For named binaries compiled for 64-bit platforms, this flaw
    can be used to trigger a buffer over-read, leading to a server crash. For named binaries compiled for
    32-bit platforms, this flaw can be used to trigger a server crash due to a buffer overflow and possibly
    also to achieve remote code execution. We have determined that standard SPNEGO implementations are
    available in the MIT and Heimdal Kerberos libraries, which support a broad range of operating systems,
    rendering the ISC implementation unnecessary and obsolete. Therefore, to reduce the attack surface for
    BIND users, we will be removing the ISC SPNEGO implementation in the April releases of BIND 9.11 and 9.16
    (it had already been dropped from BIND 9.17). We would not normally remove something from a stable ESV
    (Extended Support Version) of BIND, but since system libraries can replace the ISC SPNEGO implementation,
    we have made an exception in this case for reasons of stability and security. (CVE-2021-25216)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185345");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-May/008726.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?804e6f1b");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25214");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25215");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25216");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25216");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-chrootenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'bind-9.9.6P1-0.51.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'bind-chrootenv-9.9.6P1-0.51.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'bind-doc-9.9.6P1-0.51.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'bind-libs-32bit-9.9.6P1-0.51.26', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'bind-libs-32bit-9.9.6P1-0.51.26', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'bind-libs-9.9.6P1-0.51.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'bind-utils-9.9.6P1-0.51.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'bind-9.9.6P1-0.51.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'bind-chrootenv-9.9.6P1-0.51.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'bind-doc-9.9.6P1-0.51.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'bind-libs-32bit-9.9.6P1-0.51.26', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'bind-libs-32bit-9.9.6P1-0.51.26', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'bind-libs-9.9.6P1-0.51.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'bind-utils-9.9.6P1-0.51.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind / bind-chrootenv / bind-doc / bind-libs / bind-libs-32bit / etc');
}
