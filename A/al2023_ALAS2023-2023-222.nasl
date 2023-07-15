#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-222.
##

include('compat.inc');

if (description)
{
  script_id(177694);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/28");

  script_cve_id("CVE-2023-2650");
  script_xref(name:"IAVA", value:"2023-A-0158");

  script_name(english:"Amazon Linux 2023 : openssl, openssl-devel, openssl-libs (ALAS2023-2023-222)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by a vulnerability as referenced in the ALAS2023-2023-222 advisory.

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-222.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-2650.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update openssl --releasever 2023.1.20230628' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2650");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'openssl-3.0.8-1.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-3.0.8-1.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-3.0.8-1.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debuginfo-3.0.8-1.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debuginfo-3.0.8-1.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debuginfo-3.0.8-1.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debugsource-3.0.8-1.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debugsource-3.0.8-1.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debugsource-3.0.8-1.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-devel-3.0.8-1.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-devel-3.0.8-1.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-devel-3.0.8-1.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-3.0.8-1.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-3.0.8-1.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-3.0.8-1.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-debuginfo-3.0.8-1.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-debuginfo-3.0.8-1.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-debuginfo-3.0.8-1.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-perl-3.0.8-1.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-perl-3.0.8-1.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-perl-3.0.8-1.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-debugsource / etc");
}