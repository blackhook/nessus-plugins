#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1248-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153218);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/30");

  script_cve_id("CVE-2021-3712");
  script_xref(name:"IAVA", value:"2021-A-0395-S");

  script_name(english:"openSUSE 15 Security Update : openssl-1_1 (openSUSE-SU-2021:1248-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by a vulnerability as referenced in the
openSUSE-SU-2021:1248-1 advisory.

  - ASN.1 strings are represented internally within OpenSSL as an ASN1_STRING structure which contains a
    buffer holding the string data and a field holding the buffer length. This contrasts with normal C strings
    which are repesented as a buffer for the string data which is terminated with a NUL (0) byte. Although not
    a strict requirement, ASN.1 strings that are parsed using OpenSSL's own d2i functions (and other similar
    parsing functions) as well as any string whose value has been set with the ASN1_STRING_set() function will
    additionally NUL terminate the byte array in the ASN1_STRING structure. However, it is possible for
    applications to directly construct valid ASN1_STRING structures which do not NUL terminate the byte array
    by directly setting the data and length fields in the ASN1_STRING array. This can also happen by using
    the ASN1_STRING_set0() function. Numerous OpenSSL functions that print ASN.1 data have been found to
    assume that the ASN1_STRING byte array will be NUL terminated, even though this is not guaranteed for
    strings that have been directly constructed. Where an application requests an ASN.1 structure to be
    printed, and where that ASN.1 structure contains ASN1_STRINGs that have been directly constructed by the
    application without NUL terminating the data field, then a read buffer overrun can occur. The same thing
    can also occur during name constraints processing of certificates (for example if a certificate has been
    directly constructed by the application instead of loading it via the OpenSSL parsing functions, and the
    certificate contains non NUL terminated ASN1_STRING structures). It can also occur in the
    X509_get1_email(), X509_REQ_get1_email() and X509_get1_ocsp() functions. If a malicious actor can cause an
    application to directly construct an ASN1_STRING and then process it through one of the affected OpenSSL
    functions then this issue could be hit. This might result in a crash (causing a Denial of Service attack).
    It could also result in the disclosure of private memory contents (such as private keys, or sensitive
    plaintext). Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k). Fixed in OpenSSL 1.0.2za (Affected
    1.0.2-1.0.2y). (CVE-2021-3712)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189521");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BTAMI3TGUD3BTSIO4MHIHCP2H4HJWRWI/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3020437a");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3712");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3712");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-1_1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-1_1-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_1-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_1-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-1_1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
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
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'libopenssl-1_1-devel-1.1.1d-lp152.7.24.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libopenssl-1_1-devel-32bit-1.1.1d-lp152.7.24.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libopenssl1_1-1.1.1d-lp152.7.24.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libopenssl1_1-32bit-1.1.1d-lp152.7.24.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libopenssl1_1-hmac-1.1.1d-lp152.7.24.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libopenssl1_1-hmac-32bit-1.1.1d-lp152.7.24.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-1_1-1.1.1d-lp152.7.24.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenssl-1_1-devel / libopenssl-1_1-devel-32bit / libopenssl1_1 / etc');
}
