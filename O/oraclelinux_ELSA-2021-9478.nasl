#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-9478.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154916);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-23840", "CVE-2021-23841");
  script_xref(name:"IAVA", value:"2021-A-0103-S");
  script_xref(name:"IAVA", value:"2021-A-0193");
  script_xref(name:"IAVA", value:"2021-A-0195");
  script_xref(name:"IAVA", value:"2021-A-0480");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Linux 7 : openssl (ELSA-2021-9478)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-9478 advisory.

  - Calls to EVP_CipherUpdate, EVP_EncryptUpdate and EVP_DecryptUpdate may overflow the output length argument
    in some cases where the input length is close to the maximum permissable length for an integer on the
    platform. In such cases the return value from the function call will be 1 (indicating success), but the
    output length value will be negative. This could cause applications to behave incorrectly or crash.
    OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to
    OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out
    of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should
    upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i).
    Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x). (CVE-2021-23840)

  - The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value based
    on the issuer and serial number data contained within an X509 certificate. However it fails to correctly
    handle any errors that may occur while parsing the issuer field (which might occur if the issuer field is
    maliciously constructed). This may subsequently result in a NULL pointer deref and a crash leading to a
    potential denial of service attack. The function X509_issuer_and_serial_hash() is never directly called by
    OpenSSL itself so applications are only vulnerable if they use this function directly and they use it on
    certificates that may have been obtained from untrusted sources. OpenSSL versions 1.1.1i and below are
    affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x
    and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving
    public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should
    upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected
    1.0.2-1.0.2x). (CVE-2021-23841)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-9478.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23840");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-static");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'openssl-1.0.2k-22.ksplice1.el7_9', 'cpu':'aarch64', 'release':'7', 'el_string':'ksplice1.el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'openssl-1.0.2k-22.ksplice1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'openssl-devel-1.0.2k-22.ksplice1.el7_9', 'cpu':'aarch64', 'release':'7', 'el_string':'ksplice1.el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'openssl-devel-1.0.2k-22.ksplice1.el7_9', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'openssl-devel-1.0.2k-22.ksplice1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'openssl-libs-1.0.2k-22.ksplice1.el7_9', 'cpu':'aarch64', 'release':'7', 'el_string':'ksplice1.el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'openssl-libs-1.0.2k-22.ksplice1.el7_9', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'openssl-libs-1.0.2k-22.ksplice1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'openssl-perl-1.0.2k-22.ksplice1.el7_9', 'cpu':'aarch64', 'release':'7', 'el_string':'ksplice1.el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'openssl-perl-1.0.2k-22.ksplice1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'openssl-static-1.0.2k-22.ksplice1.el7_9', 'cpu':'aarch64', 'release':'7', 'el_string':'ksplice1.el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'openssl-static-1.0.2k-22.ksplice1.el7_9', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'openssl-static-1.0.2k-22.ksplice1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssl / openssl-devel / openssl-libs / etc');
}
