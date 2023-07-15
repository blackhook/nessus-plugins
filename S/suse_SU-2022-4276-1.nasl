#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:4276-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(168309);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2017-11591",
    "CVE-2018-11531",
    "CVE-2018-17581",
    "CVE-2018-20097",
    "CVE-2018-20098",
    "CVE-2018-20099",
    "CVE-2019-13109",
    "CVE-2019-13110",
    "CVE-2019-17402",
    "CVE-2021-29473",
    "CVE-2021-32815"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:4276-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : exiv2 (SUSE-SU-2022:4276-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:4276-1 advisory.

  - There is a Floating point exception in the Exiv2::ValueType function in Exiv2 0.26 that will lead to a
    remote denial of service attack via crafted input. (CVE-2017-11591)

  - Exiv2 0.26 has a heap-based buffer overflow in getData in preview.cpp. (CVE-2018-11531)

  - CiffDirectory::readDirectory() at crwimage_int.cpp in Exiv2 0.26 has excessive stack consumption due to a
    recursive function, leading to Denial of service. (CVE-2018-17581)

  - There is a SEGV in Exiv2::Internal::TiffParserWorker::findPrimaryGroups of tiffimage_int.cpp in Exiv2
    0.27-RC3. A crafted input will lead to a remote denial of service attack. (CVE-2018-20097)

  - There is a heap-based buffer over-read in Exiv2::Jp2Image::encodeJp2Header of jp2image.cpp in Exiv2
    0.27-RC3. A crafted input will lead to a remote denial of service attack. (CVE-2018-20098)

  - There is an infinite loop in Exiv2::Jp2Image::encodeJp2Header of jp2image.cpp in Exiv2 0.27-RC3. A crafted
    input will lead to a remote denial of service attack. (CVE-2018-20099)

  - An integer overflow in Exiv2 through 0.27.1 allows an attacker to cause a denial of service (SIGSEGV) via
    a crafted PNG image file, because PngImage::readMetadata mishandles a chunkLength - iccOffset subtraction.
    (CVE-2019-13109)

  - A CiffDirectory::readDirectory integer overflow and out-of-bounds read in Exiv2 through 0.27.1 allows an
    attacker to cause a denial of service (SIGSEGV) via a crafted CRW image file. (CVE-2019-13110)

  - Exiv2 0.27.2 allows attackers to trigger a crash in Exiv2::getULong in types.cpp when called from
    Exiv2::Internal::CiffDirectory::readDirectory in crwimage_int.cpp, because there is no validation of the
    relationship of the total size to the offset and size. (CVE-2019-17402)

  - Exiv2 is a C++ library and a command-line utility to read, write, delete and modify Exif, IPTC, XMP and
    ICC image metadata. An out-of-bounds read was found in Exiv2 versions v0.27.3 and earlier. Exiv2 is a
    command-line utility and C++ library for reading, writing, deleting, and modifying the metadata of image
    files. The out-of-bounds read is triggered when Exiv2 is used to write metadata into a crafted image file.
    An attacker could potentially exploit the vulnerability to cause a denial of service by crashing Exiv2, if
    they can trick the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered
    when writing the metadata, which is a less frequently used Exiv2 operation than reading the metadata. For
    example, to trigger the bug in the Exiv2 command-line application, you need to add an extra command-line
    argument such as `insert`. The bug is fixed in version v0.27.4. Please see our security policy for
    information about Exiv2 security. (CVE-2021-29473)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. The assertion failure is triggered when Exiv2 is used to modify the metadata of a crafted
    image file. An attacker could potentially exploit the vulnerability to cause a denial of service, if they
    can trick the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when
    modifying the metadata, which is a less frequently used Exiv2 operation than reading the metadata. For
    example, to trigger the bug in the Exiv2 command-line application, you need to add an extra command-line
    argument such as `fi`. ### Patches The bug is fixed in version v0.27.5. ### References Regression test and
    bug fix: #1739 ### For more information Please see our [security
    policy](https://github.com/Exiv2/exiv2/security/policy) for information about Exiv2 security.
    (CVE-2021-32815)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1050257");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1095070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1110282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1119559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1119560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1119562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1142677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1142678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1153577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186231");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189337");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-November/013143.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f51feb96");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-11591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-11531");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-17581");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20097");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-13109");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-13110");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29473");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32815");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11531");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libexiv2-26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libexiv2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.3)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2/3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'exiv2-0.26-150000.6.26.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'exiv2-lang-0.26-150000.6.26.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libexiv2-26-32bit-0.26-150000.6.26.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libexiv2-doc-0.26-150000.6.26.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libexiv2-26-0.26-150000.6.26.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'libexiv2-devel-0.26-150000.6.26.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'exiv2 / exiv2-lang / libexiv2-26 / libexiv2-26-32bit / libexiv2-devel / etc');
}
