#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2020:14560-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150634);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-1971");
  script_xref(name:"SuSE", value:"SUSE-SU-2020:14560-1");
  script_xref(name:"IAVA", value:"2021-A-0038");
  script_xref(name:"IAVA", value:"2020-A-0566-S");
  script_xref(name:"IAVA", value:"2021-A-0193");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"SUSE SLES11 Security Update : openssl1 (SUSE-SU-2020:14560-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by a vulnerability as referenced in the SUSE-
SU-2020:14560-1 advisory.

  - The X.509 GeneralName type is a generic type for representing different types of names. One of those name
    types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different
    instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both
    GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a
    possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1)
    Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in
    an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp
    authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an
    attacker can control both items being compared then that attacker could trigger a crash. For example if
    the attacker can trick a client or server into checking a malicious certificate against a malicious CRL
    then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a
    certificate. This checking happens prior to the signatures on the certificate and CRL being verified.
    OpenSSL's s_server, s_client and verify tools have support for the -crl_download option which implements
    automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an
    unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of
    EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will
    accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue.
    Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected
    1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w). (CVE-2020-1971)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179491");
  # https://lists.suse.com/pipermail/sle-security-updates/2020-December/007950.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c1ee0cc");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-1971");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1971");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl1-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'libopenssl1-devel-1.0.1g-0.58.30', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'libopenssl1_0_0-1.0.1g-0.58.30', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'libopenssl1_0_0-32bit-1.0.1g-0.58.30', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'libopenssl1_0_0-32bit-1.0.1g-0.58.30', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'openssl1-1.0.1g-0.58.30', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'openssl1-doc-1.0.1g-0.58.30', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'libopenssl1-devel-1.0.1g-0.58.30', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'libopenssl1_0_0-1.0.1g-0.58.30', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'libopenssl1_0_0-32bit-1.0.1g-0.58.30', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'libopenssl1_0_0-32bit-1.0.1g-0.58.30', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'openssl1-1.0.1g-0.58.30', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'openssl1-doc-1.0.1g-0.58.30', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenssl1-devel / libopenssl1_0_0 / libopenssl1_0_0-32bit / openssl1 / etc');
}
