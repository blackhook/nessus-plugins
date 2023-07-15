#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2620-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(177607);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/25");

  script_cve_id("CVE-2023-1255", "CVE-2023-2650");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2620-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : openssl-3 (SUSE-SU-2023:2620-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:2620-1 advisory.

  - Issue summary: The AES-XTS cipher decryption implementation for 64 bit ARM platform contains a bug that
    could cause it to read past the input buffer, leading to a crash. Impact summary: Applications that use
    the AES-XTS algorithm on the 64 bit ARM platform can crash in rare circumstances. The AES-XTS algorithm is
    usually used for disk encryption. The AES-XTS cipher decryption implementation for 64 bit ARM platform
    will read past the end of the ciphertext buffer if the ciphertext size is 4 mod 5 in 16 byte blocks, e.g.
    144 bytes or 1024 bytes. If the memory after the ciphertext buffer is unmapped, this will trigger a crash
    which results in a denial of service. If an attacker can control the size and location of the ciphertext
    buffer being decrypted by an application using AES-XTS on 64 bit ARM, the application is affected. This is
    fairly unlikely making this issue a Low severity one. (CVE-2023-1255)

  - Issue summary: Processing some specially crafted ASN.1 object identifiers or data containing them may be
    very slow. Impact summary: Applications that use OBJ_obj2txt() directly, or use any of the OpenSSL
    subsystems OCSP, PKCS7/SMIME, CMS, CMP/CRMF or TS with no message size limit may experience notable to
    very long delays when processing those messages, which may lead to a Denial of Service. An OBJECT
    IDENTIFIER is composed of a series of numbers - sub-identifiers - most of which have no size limit.
    OBJ_obj2txt() may be used to translate an ASN.1 OBJECT IDENTIFIER given in DER encoding form (using the
    OpenSSL type ASN1_OBJECT) to its canonical numeric text form, which are the sub-identifiers of the OBJECT
    IDENTIFIER in decimal form, separated by periods. When one of the sub-identifiers in the OBJECT IDENTIFIER
    is very large (these are sizes that are seen as absurdly large, taking up tens or hundreds of KiBs), the
    translation to a decimal number in text may take a very long time. The time complexity is O(n^2) with 'n'
    being the size of the sub-identifiers in bytes (*). With OpenSSL 3.0, support to fetch cryptographic
    algorithms using names / identifiers in string form was introduced. This includes using OBJECT IDENTIFIERs
    in canonical numeric text form as identifiers for fetching algorithms. Such OBJECT IDENTIFIERs may be
    received through the ASN.1 structure AlgorithmIdentifier, which is commonly used in multiple protocols to
    specify what cryptographic algorithm should be used to sign or verify, encrypt or decrypt, or digest
    passed data. Applications that call OBJ_obj2txt() directly with untrusted data are affected, with any
    version of OpenSSL. If the use is for the mere purpose of display, the severity is considered low. In
    OpenSSL 3.0 and newer, this affects the subsystems OCSP, PKCS7/SMIME, CMS, CMP/CRMF or TS. It also impacts
    anything that processes X.509 certificates, including simple things like verifying its signature. The
    impact on TLS is relatively low, because all versions of OpenSSL have a 100KiB limit on the peer's
    certificate chain. Additionally, this only impacts clients, or servers that have explicitly enabled client
    authentication. In OpenSSL 1.1.1 and 1.0.2, this only affects displaying diverse objects, such as X.509
    certificates. This is assumed to not happen in such a way that it would cause a Denial of Service, so
    these versions are considered not affected by this issue in such a way that it would be cause for concern,
    and the severity is therefore considered low. (CVE-2023-2650)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211430");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-June/030015.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1255");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2650");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2650");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl-3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libopenssl-3-devel-3.0.8-150500.5.3.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libopenssl-3-devel-3.0.8-150500.5.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libopenssl3-3.0.8-150500.5.3.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libopenssl3-3.0.8-150500.5.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'openssl-3-3.0.8-150500.5.3.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'openssl-3-3.0.8-150500.5.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libopenssl-3-devel-3.0.8-150500.5.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libopenssl-3-devel-32bit-3.0.8-150500.5.3.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libopenssl3-3.0.8-150500.5.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libopenssl3-32bit-3.0.8-150500.5.3.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'openssl-3-3.0.8-150500.5.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'openssl-3-doc-3.0.8-150500.5.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenssl-3-devel / libopenssl-3-devel-32bit / libopenssl3 / etc');
}
