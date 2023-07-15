#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:14700-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150604);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");

  script_cve_id(
    "CVE-2020-36221",
    "CVE-2020-36222",
    "CVE-2020-36223",
    "CVE-2020-36224",
    "CVE-2020-36225",
    "CVE-2020-36226",
    "CVE-2020-36227",
    "CVE-2020-36228",
    "CVE-2020-36229",
    "CVE-2020-36230",
    "CVE-2021-27212"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:14700-1");
  script_xref(name:"IAVB", value:"2021-B-0014");

  script_name(english:"SUSE SLES11 Security Update : openldap2 (SUSE-SU-2021:14700-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:14700-1 advisory.

  - An integer underflow was discovered in OpenLDAP before 2.4.57 leading to slapd crashes in the Certificate
    Exact Assertion processing, resulting in denial of service (schema_init.c serialNumberAndIssuerCheck).
    (CVE-2020-36221)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to an assertion failure in slapd in the
    saslAuthzTo validation, resulting in denial of service. (CVE-2020-36222)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to a slapd crash in the Values Return Filter
    control handling, resulting in denial of service (double free and out-of-bounds read). (CVE-2020-36223)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to an invalid pointer free and slapd crash in the
    saslAuthzTo processing, resulting in denial of service. (CVE-2020-36224)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to a double free and slapd crash in the
    saslAuthzTo processing, resulting in denial of service. (CVE-2020-36225)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to a memch->bv_len miscalculation and slapd crash
    in the saslAuthzTo processing, resulting in denial of service. (CVE-2020-36226)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to an infinite loop in slapd with the cancel_extop
    Cancel operation, resulting in denial of service. (CVE-2020-36227)

  - An integer underflow was discovered in OpenLDAP before 2.4.57 leading to a slapd crash in the Certificate
    List Exact Assertion processing, resulting in denial of service. (CVE-2020-36228)

  - A flaw was discovered in ldap_X509dn2bv in OpenLDAP before 2.4.57 leading to a slapd crash in the X.509 DN
    parsing in ad_keystring, resulting in denial of service. (CVE-2020-36229)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading in an assertion failure in slapd in the X.509 DN
    parsing in decode.c ber_next_element, resulting in denial of service. (CVE-2020-36230)

  - In OpenLDAP through 2.4.57 and 2.5.x through 2.5.1alpha, an assertion failure in slapd can occur in the
    issuerAndThisUpdateCheck function via a crafted packet, resulting in a denial of service (daemon exit) via
    a short timestamp. This is related to schema_init.c and checkTime. (CVE-2021-27212)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182279");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184020");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-April/008644.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7000c2a0");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36221");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36222");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36223");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36224");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36225");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36226");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36227");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36228");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36229");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36230");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27212");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27212");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:compat-libldap-2_3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-2_4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-2_4-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-openssl1-2_4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-openssl1-2_4-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-openssl1-2_4-2-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-back-meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-client-openssl1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-openssl1");
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
if (os_ver == "SLES11" && (! preg(pattern:"^(0|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP0/4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'libldap-openssl1-2_4-2-2.4.26-0.74.26', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'libldap-openssl1-2_4-2-32bit-2.4.26-0.74.26', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'libldap-openssl1-2_4-2-32bit-2.4.26-0.74.26', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'openldap2-client-openssl1-2.4.26-0.74.26', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'openldap2-openssl1-2.4.26-0.74.26', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'compat-libldap-2_3-0-2.3.37-2.74.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libldap-2_4-2-2.4.26-0.74.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libldap-2_4-2-32bit-2.4.26-0.74.26', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libldap-2_4-2-32bit-2.4.26-0.74.26', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'openldap2-2.4.26-0.74.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'openldap2-back-meta-2.4.26-0.74.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'openldap2-client-2.4.26-0.74.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libldap-openssl1-2_4-2-2.4.26-0.74.26', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'libldap-openssl1-2_4-2-32bit-2.4.26-0.74.26', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'libldap-openssl1-2_4-2-32bit-2.4.26-0.74.26', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'openldap2-client-openssl1-2.4.26-0.74.26', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'openldap2-openssl1-2.4.26-0.74.26', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'compat-libldap-2_3-0-2.3.37-2.74.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libldap-2_4-2-2.4.26-0.74.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libldap-2_4-2-32bit-2.4.26-0.74.26', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libldap-2_4-2-32bit-2.4.26-0.74.26', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'openldap2-2.4.26-0.74.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'openldap2-back-meta-2.4.26-0.74.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'openldap2-client-2.4.26-0.74.26', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'compat-libldap-2_3-0 / libldap-2_4-2 / libldap-2_4-2-32bit / etc');
}
