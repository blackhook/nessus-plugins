#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3889-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(167062);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2017-1000128",
    "CVE-2019-13108",
    "CVE-2019-13111",
    "CVE-2020-19716",
    "CVE-2021-29457",
    "CVE-2021-29463",
    "CVE-2021-29470",
    "CVE-2021-29623",
    "CVE-2021-31291",
    "CVE-2021-32617",
    "CVE-2021-34334",
    "CVE-2021-37620",
    "CVE-2021-37621",
    "CVE-2021-37622",
    "CVE-2021-37623"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3889-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : exiv2 (SUSE-SU-2022:3889-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:3889-1 advisory.

  - Exiv2 0.26 contains a stack out of bounds read in JPEG2000 parser (CVE-2017-1000128)

  - An integer overflow in Exiv2 through 0.27.1 allows an attacker to cause a denial of service (SIGSEGV) via
    a crafted PNG image file, because PngImage::readMetadata mishandles a zero value for iccOffset.
    (CVE-2019-13108)

  - A WebPImage::decodeChunks integer overflow in Exiv2 through 0.27.1 allows an attacker to cause a denial of
    service (large heap allocation followed by a very long running loop) via a crafted WEBP image file.
    (CVE-2019-13111)

  - A buffer overflow vulnerability in the Databuf function in types.cpp of Exiv2 v0.27.1 leads to a denial of
    service (DOS). (CVE-2020-19716)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. A heap buffer overflow was found in Exiv2 versions v0.27.3 and earlier. The heap overflow
    is triggered when Exiv2 is used to write metadata into a crafted image file. An attacker could potentially
    exploit the vulnerability to gain code execution, if they can trick the victim into running Exiv2 on a
    crafted image file. Note that this bug is only triggered when _writing_ the metadata, which is a less
    frequently used Exiv2 operation than _reading_ the metadata. For example, to trigger the bug in the Exiv2
    command-line application, you need to add an extra command-line argument such as `insert`. The bug is
    fixed in version v0.27.4. (CVE-2021-29457)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in Exiv2 versions v0.27.3 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to write metadata into a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial of service by crashing Exiv2, if they can trick
    the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when writing
    the metadata, which is a less frequently used Exiv2 operation than reading the metadata. For example, to
    trigger the bug in the Exiv2 command-line application, you need to add an extra command-line argument such
    as `insert`. The bug is fixed in version v0.27.4. (CVE-2021-29463)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in Exiv2 versions v0.27.3 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to write metadata into a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial of service by crashing Exiv2, if they can trick
    the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when writing
    the metadata, which is a less frequently used Exiv2 operation than reading the metadata. For example, to
    trigger the bug in the Exiv2 command-line application, you need to add an extra command-line argument such
    as insert. The bug is fixed in version v0.27.4. (CVE-2021-29470)

  - Exiv2 is a C++ library and a command-line utility to read, write, delete and modify Exif, IPTC, XMP and
    ICC image metadata. A read of uninitialized memory was found in Exiv2 versions v0.27.3 and earlier. Exiv2
    is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata of
    image files. The read of uninitialized memory is triggered when Exiv2 is used to read the metadata of a
    crafted image file. An attacker could potentially exploit the vulnerability to leak a few bytes of stack
    memory, if they can trick the victim into running Exiv2 on a crafted image file. The bug is fixed in
    version v0.27.4. (CVE-2021-29623)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An inefficient algorithm (quadratic complexity) was found in Exiv2 versions v0.27.3 and
    earlier. The inefficient algorithm is triggered when Exiv2 is used to write metadata into a crafted image
    file. An attacker could potentially exploit the vulnerability to cause a denial of service, if they can
    trick the victim into running Exiv2 on a crafted image file. The bug is fixed in version v0.27.4. Note
    that this bug is only triggered when _writing_ the metadata, which is a less frequently used Exiv2
    operation than _reading_ the metadata. For example, to trigger the bug in the Exiv2 command-line
    application, you need to add an extra command-line argument such as `rm`. (CVE-2021-32617)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An infinite loop is triggered when Exiv2 is used to read the metadata of a crafted image
    file. An attacker could potentially exploit the vulnerability to cause a denial of service, if they can
    trick the victim into running Exiv2 on a crafted image file. The bug is fixed in version v0.27.5.
    (CVE-2021-34334)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in Exiv2 versions v0.27.4 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to read the metadata of a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial of service, if they can trick the victim into
    running Exiv2 on a crafted image file. The bug is fixed in version v0.27.5. (CVE-2021-37620)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An infinite loop was found in Exiv2 versions v0.27.4 and earlier. The infinite loop is
    triggered when Exiv2 is used to print the metadata of a crafted image file. An attacker could potentially
    exploit the vulnerability to cause a denial of service, if they can trick the victim into running Exiv2 on
    a crafted image file. Note that this bug is only triggered when printing the image ICC profile, which is a
    less frequently used Exiv2 operation that requires an extra command line option (`-p C`). The bug is fixed
    in version v0.27.5. (CVE-2021-37621)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An infinite loop was found in Exiv2 versions v0.27.4 and earlier. The infinite loop is
    triggered when Exiv2 is used to modify the metadata of a crafted image file. An attacker could potentially
    exploit the vulnerability to cause a denial of service, if they can trick the victim into running Exiv2 on
    a crafted image file. Note that this bug is only triggered when deleting the IPTC data, which is a less
    frequently used Exiv2 operation that requires an extra command line option (`-d I rm`). The bug is fixed
    in version v0.27.5. (CVE-2021-37622, CVE-2021-37623)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1068871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1142675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1142679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185913");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189338");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-November/012825.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2410a1d");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-1000128");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-13108");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-13111");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-19716");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29457");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29463");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29470");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-31291");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32617");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-34334");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37620");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37621");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37622");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37623");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31291");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libexiv2-26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libexiv2-27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libexiv2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libexiv2-xmp-static");
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
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libexiv2-26-0.26-150400.9.16.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libexiv2-26-0.26-150400.9.16.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libexiv2-27-0.27.5-150400.15.4.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libexiv2-27-0.27.5-150400.15.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libexiv2-devel-0.27.5-150400.15.4.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libexiv2-devel-0.27.5-150400.15.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libexiv2-xmp-static-0.27.5-150400.15.4.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libexiv2-xmp-static-0.27.5-150400.15.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'exiv2-0.27.5-150400.15.4.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'exiv2-lang-0.27.5-150400.15.4.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libexiv2-26-0.26-150400.9.16.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libexiv2-26-32bit-0.26-150400.9.16.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libexiv2-27-0.27.5-150400.15.4.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libexiv2-27-32bit-0.27.5-150400.15.4.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libexiv2-devel-0.27.5-150400.15.4.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libexiv2-xmp-static-0.27.5-150400.15.4.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'exiv2 / exiv2-lang / libexiv2-26 / libexiv2-26-32bit / libexiv2-27 / etc');
}
