#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:14598-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150515);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");

  script_cve_id(
    "CVE-2020-19667",
    "CVE-2020-25664",
    "CVE-2020-25666",
    "CVE-2020-27751",
    "CVE-2020-27752",
    "CVE-2020-27753",
    "CVE-2020-27754",
    "CVE-2020-27755",
    "CVE-2020-27759",
    "CVE-2020-27760",
    "CVE-2020-27761",
    "CVE-2020-27763",
    "CVE-2020-27765",
    "CVE-2020-27767",
    "CVE-2020-27768",
    "CVE-2020-27769",
    "CVE-2020-27771",
    "CVE-2020-27772",
    "CVE-2020-27775"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:14598-1");
  script_xref(name:"IAVB", value:"2020-B-0042-S");
  script_xref(name:"IAVB", value:"2020-B-0076-S");

  script_name(english:"SUSE SLES11 Security Update : ImageMagick (SUSE-SU-2021:14598-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:14598-1 advisory.

  - Stack-based buffer overflow and unconditional jump in ReadXPMImage in coders/xpm.c in ImageMagick
    7.0.10-7. (CVE-2020-19667)

  - In WriteOnePNGImage() of the PNG coder at coders/png.c, an improper call to AcquireVirtualMemory() and
    memset() allows for an out-of-bounds write later when PopShortPixel() from MagickCore/quantum-private.h is
    called. The patch fixes the calls by adding 256 to rowbytes. An attacker who is able to supply a specially
    crafted image could affect availability with a low impact to data integrity. This flaw affects ImageMagick
    versions prior to 6.9.10-68 and 7.0.8-68. (CVE-2020-25664)

  - There are 4 places in HistogramCompare() in MagickCore/histogram.c where an integer overflow is possible
    during simple math calculations. This occurs in the rgb values and `count` value for a color. The patch
    uses casts to `ssize_t` type for these calculations, instead of `int`. This flaw could impact application
    reliability in the event that ImageMagick processes a crafted input file. This flaw affects ImageMagick
    versions prior to 7.0.9-0. (CVE-2020-25666)

  - A flaw was found in ImageMagick in MagickCore/quantum-export.c. An attacker who submits a crafted file
    that is processed by ImageMagick could trigger undefined behavior in the form of values outside the range
    of type `unsigned long long` as well as a shift exponent that is too large for 64-bit type. This would
    most likely lead to an impact to application availability, but could potentially cause other problems
    related to undefined behavior. This flaw affects ImageMagick versions prior to 7.0.9-0. (CVE-2020-27751)

  - A flaw was found in ImageMagick in MagickCore/quantum-private.h. An attacker who submits a crafted file
    that is processed by ImageMagick could trigger a heap buffer overflow. This would most likely lead to an
    impact to application availability, but could potentially lead to an impact to data integrity as well.
    This flaw affects ImageMagick versions prior to 7.0.9-0. (CVE-2020-27752)

  - There are several memory leaks in the MIFF coder in /coders/miff.c due to improper image depth values,
    which can be triggered by a specially crafted input file. These leaks could potentially lead to an impact
    to application availability or cause a denial of service. It was originally reported that the issues were
    in `AcquireMagickMemory()` because that is where LeakSanitizer detected the leaks, but the patch resolves
    issues in the MIFF coder, which incorrectly handles data being passed to `AcquireMagickMemory()`. This
    flaw affects ImageMagick versions prior to 7.0.9-0. (CVE-2020-27753)

  - In IntensityCompare() of /magick/quantize.c, there are calls to PixelPacketIntensity() which could return
    overflowed values to the caller when ImageMagick processes a crafted input file. To mitigate this, the
    patch introduces and uses the ConstrainPixelIntensity() function, which forces the pixel intensities to be
    within the proper bounds in the event of an overflow. This flaw affects ImageMagick versions prior to
    6.9.10-69 and 7.0.8-69. (CVE-2020-27754)

  - in SetImageExtent() of /MagickCore/image.c, an incorrect image depth size can cause a memory leak because
    the code which checks for the proper image depth size does not reset the size in the event there is an
    invalid size. The patch resets the depth to a proper size before throwing an exception. The memory leak
    can be triggered by a crafted input file that is processed by ImageMagick and could cause an impact to
    application reliability, such as denial of service. This flaw affects ImageMagick versions prior to
    7.0.9-0. (CVE-2020-27755)

  - In IntensityCompare() of /MagickCore/quantize.c, a double value was being casted to int and returned,
    which in some cases caused a value outside the range of type `int` to be returned. The flaw could be
    triggered by a crafted input file under certain conditions when processed by ImageMagick. Red Hat Product
    Security marked this as Low severity because although it could potentially lead to an impact to
    application availability, no specific impact was shown in this case. This flaw affects ImageMagick
    versions prior to 7.0.8-68. (CVE-2020-27759)

  - In `GammaImage()` of /MagickCore/enhance.c, depending on the `gamma` value, it's possible to trigger a
    divide-by-zero condition when a crafted input file is processed by ImageMagick. This could lead to an
    impact to application availability. The patch uses the `PerceptibleReciprocal()` to prevent the divide-by-
    zero from occurring. This flaw affects ImageMagick versions prior to ImageMagick 7.0.8-68.
    (CVE-2020-27760)

  - WritePALMImage() in /coders/palm.c used size_t casts in several areas of a calculation which could lead to
    values outside the range of representable type `unsigned long` undefined behavior when a crafted input
    file was processed by ImageMagick. The patch casts to `ssize_t` instead to avoid this issue. Red Hat
    Product Security marked the Severity as Low because although it could potentially lead to an impact to
    application availability, no specific impact was shown in this case. This flaw affects ImageMagick
    versions prior to ImageMagick 7.0.9-0. (CVE-2020-27761)

  - A flaw was found in ImageMagick in MagickCore/resize.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of math division by zero. This would
    most likely lead to an impact to application availability, but could potentially cause other problems
    related to undefined behavior. This flaw affects ImageMagick versions prior to 7.0.8-68. (CVE-2020-27763)

  - A flaw was found in ImageMagick in MagickCore/segment.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of math division by zero. This would
    most likely lead to an impact to application availability, but could potentially cause other problems
    related to undefined behavior. This flaw affects ImageMagick versions prior to 7.0.9-0. (CVE-2020-27765)

  - A flaw was found in ImageMagick in MagickCore/quantum.h. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of values outside the range of types
    `float` and `unsigned char`. This would most likely lead to an impact to application availability, but
    could potentially cause other problems related to undefined behavior. This flaw affects ImageMagick
    versions prior to 7.0.9-0. (CVE-2020-27767)

  - In ImageMagick, there is an outside the range of representable values of type 'unsigned int' at
    MagickCore/quantum-private.h. This flaw affects ImageMagick versions prior to 7.0.9-0. (CVE-2020-27768)

  - In ImageMagick versions before 7.0.9-0, there are outside the range of representable values of type
    'float' at MagickCore/quantize.c. (CVE-2020-27769)

  - In RestoreMSCWarning() of /coders/pdf.c there are several areas where calls to GetPixelIndex() could
    result in values outside the range of representable for the unsigned char type. The patch casts the return
    value of GetPixelIndex() to ssize_t type to avoid this bug. This undefined behavior could be triggered
    when ImageMagick processes a crafted pdf file. Red Hat Product Security marked this as Low severity
    because although it could potentially lead to an impact to application availability, no specific impact
    was demonstrated in this case. This flaw affects ImageMagick versions prior to 7.0.9-0. (CVE-2020-27771)

  - A flaw was found in ImageMagick in coders/bmp.c. An attacker who submits a crafted file that is processed
    by ImageMagick could trigger undefined behavior in the form of values outside the range of type `unsigned
    int`. This would most likely lead to an impact to application availability, but could potentially cause
    other problems related to undefined behavior. This flaw affects ImageMagick versions prior to 7.0.9-0.
    (CVE-2020-27772)

  - A flaw was found in ImageMagick in MagickCore/quantum.h. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of values outside the range of type
    unsigned char. This would most likely lead to an impact to application availability, but could potentially
    cause other problems related to undefined behavior. This flaw affects ImageMagick versions prior to
    7.0.9-0. (CVE-2020-27775)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179311");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179321");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179397");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-January/008218.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?380276b3");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-19667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25666");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27751");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27752");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27755");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27760");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27761");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27765");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27767");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27768");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27769");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27771");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27775");
  script_set_attribute(attribute:"solution", value:
"Update the affected libMagickCore1 and / or libMagickCore1-32bit packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-19667");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore1-32bit");
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
    {'reference':'libMagickCore1-32bit-6.4.3.6-78.135', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libMagickCore1-32bit-6.4.3.6-78.135', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libMagickCore1-6.4.3.6-78.135', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libMagickCore1-32bit-6.4.3.6-78.135', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libMagickCore1-32bit-6.4.3.6-78.135', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libMagickCore1-6.4.3.6-78.135', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libMagickCore1 / libMagickCore1-32bit');
}
