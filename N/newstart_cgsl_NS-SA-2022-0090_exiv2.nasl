#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0090. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167490);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2019-17402",
    "CVE-2021-3482",
    "CVE-2021-29457",
    "CVE-2021-29458",
    "CVE-2021-29463",
    "CVE-2021-29464",
    "CVE-2021-29470",
    "CVE-2021-29473",
    "CVE-2021-29623",
    "CVE-2021-31291",
    "CVE-2021-31292",
    "CVE-2021-32617",
    "CVE-2021-37618",
    "CVE-2021-37619"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : exiv2 Multiple Vulnerabilities (NS-SA-2022-0090)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has exiv2 packages installed that are affected by multiple
vulnerabilities:

  - Exiv2 0.27.2 allows attackers to trigger a crash in Exiv2::getULong in types.cpp when called from
    Exiv2::Internal::CiffDirectory::readDirectory in crwimage_int.cpp, because there is no validation of the
    relationship of the total size to the offset and size. (CVE-2019-17402)

  - A flaw was found in Exiv2 in versions before and including 0.27.4-RC1. Improper input validation of the
    rawData.size property in Jp2Image::readMetadata() in jp2image.cpp can lead to a heap-based buffer overflow
    via a crafted JPG image containing malicious EXIF data. (CVE-2021-3482)

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
    as insert. The bug is fixed in version v0.27.4. (CVE-2021-29458, CVE-2021-29470)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in Exiv2 versions v0.27.3 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to write metadata into a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial of service by crashing Exiv2, if they can trick
    the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when writing
    the metadata, which is a less frequently used Exiv2 operation than reading the metadata. For example, to
    trigger the bug in the Exiv2 command-line application, you need to add an extra command-line argument such
    as `insert`. The bug is fixed in version v0.27.4. (CVE-2021-29463)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0090");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-17402");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29457");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29458");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29463");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29464");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29470");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29473");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29623");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-31291");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-31292");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-32617");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3482");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-37618");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-37619");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL exiv2 packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31291");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:exiv2-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'exiv2-libs-0.27.4-5.el8'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'exiv2');
}
