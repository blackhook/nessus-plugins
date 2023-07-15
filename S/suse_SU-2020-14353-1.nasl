#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2020:14353-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150644);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");

  script_cve_id("CVE-2019-13057", "CVE-2019-13565");
  script_xref(name:"SuSE", value:"SUSE-SU-2020:14353-1");

  script_name(english:"SUSE SLES11 Security Update : openldap2 (SUSE-SU-2020:14353-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2020:14353-1 advisory.

  - An issue was discovered in the server in OpenLDAP before 2.4.48. When the server administrator delegates
    rootDN (database admin) privileges for certain databases but wants to maintain isolation (e.g., for multi-
    tenant deployments), slapd does not properly stop a rootDN from requesting authorization as an identity
    from another database during a SASL bind or with a proxyAuthz (RFC 4370) control. (It is not a common
    configuration to deploy a system where the server administrator and a DB administrator enjoy different
    levels of trust.) (CVE-2019-13057)

  - An issue was discovered in OpenLDAP 2.x before 2.4.48. When using SASL authentication and session
    encryption, and relying on the SASL security layers in slapd access controls, it is possible to obtain
    access that would otherwise be denied via a simple bind for any identity covered in those ACLs. After the
    first SASL bind is completed, the sasl_ssf value is retained for all new non-SASL connections. Depending
    on the ACL configuration, this can affect different types of operations (searches, modifications, etc.).
    In other words, a successful authorization step completed by one user affects the authorization
    requirement for a different user. (CVE-2019-13565)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1143194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1143273");
  # https://lists.suse.com/pipermail/sle-security-updates/2020-April/006767.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f429c0a");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-13057");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-13565");
  script_set_attribute(attribute:"solution", value:
"Update the affected libldap-openssl1-2_4-2, libldap-openssl1-2_4-2-32bit, openldap2-client-openssl1 and / or
openldap2-openssl1 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13565");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-openssl1-2_4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-openssl1-2_4-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-openssl1-2_4-2-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-client-openssl1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-openssl1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
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
if (os_ver == "SLES11" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP0", os_ver + " SP" + sp);

pkgs = [
    {'reference':'libldap-openssl1-2_4-2-2.4.26-0.74.6', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'libldap-openssl1-2_4-2-32bit-2.4.26-0.74.6', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'libldap-openssl1-2_4-2-32bit-2.4.26-0.74.6', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'openldap2-client-openssl1-2.4.26-0.74.6', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'openldap2-openssl1-2.4.26-0.74.6', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'libldap-openssl1-2_4-2-2.4.26-0.74.6', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'libldap-openssl1-2_4-2-32bit-2.4.26-0.74.6', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'libldap-openssl1-2_4-2-32bit-2.4.26-0.74.6', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'openldap2-client-openssl1-2.4.26-0.74.6', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'openldap2-openssl1-2.4.26-0.74.6', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'}
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
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libldap-openssl1-2_4-2 / libldap-openssl1-2_4-2-32bit / etc');
}
