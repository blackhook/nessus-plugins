#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0186. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129906);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2017-18233",
    "CVE-2017-18234",
    "CVE-2017-18236",
    "CVE-2017-18238",
    "CVE-2018-7730"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : exempi Multiple Vulnerabilities (NS-SA-2019-0186)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has exempi packages installed that are affected by
multiple vulnerabilities:

  - An issue was discovered in Exempi before 2.4.3. It
    allows remote attackers to cause a denial of service
    (invalid memcpy with resultant use-after-free) or
    possibly have unspecified other impact via a .pdf file
    containing JPEG data, related to
    XMPFiles/source/FormatSupport/ReconcileTIFF.cpp,
    XMPFiles/source/FormatSupport/TIFF_MemoryReader.cpp, and
    XMPFiles/source/FormatSupport/TIFF_Support.hpp.
    (CVE-2017-18234)

  - An issue was discovered in Exempi before 2.4.4. The
    TradQT_Manager::ParseCachedBoxes function in
    XMPFiles/source/FormatSupport/QuickTime_Support.cpp
    allows remote attackers to cause a denial of service
    (infinite loop) via crafted XMP data in a .qt file.
    (CVE-2017-18238)

  - An issue was discovered in Exempi through 2.4.4. A
    certain case of a 0xffffffff length is mishandled in
    XMPFiles/source/FormatSupport/PSIR_FileWriter.cpp,
    leading to a heap-based buffer over-read in the
    PSD_MetaHandler::CacheFileData() function.
    (CVE-2018-7730)

  - An issue was discovered in Exempi before 2.4.4. The
    ASF_Support::ReadHeaderObject function in
    XMPFiles/source/FormatSupport/ASF_Support.cpp allows
    remote attackers to cause a denial of service (infinite
    loop) via a crafted .asf file. (CVE-2017-18236)

  - An issue was discovered in Exempi before 2.4.4. Integer
    overflow in the Chunk class in
    XMPFiles/source/FormatSupport/RIFF.cpp allows remote
    attackers to cause a denial of service (infinite loop)
    via crafted XMP data in a .avi file. (CVE-2017-18233)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0186");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL exempi packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18234");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "exempi-2.2.0-9.el7",
    "exempi-debuginfo-2.2.0-9.el7",
    "exempi-devel-2.2.0-9.el7"
  ],
  "CGSL MAIN 5.04": [
    "exempi-2.2.0-9.el7",
    "exempi-debuginfo-2.2.0-9.el7",
    "exempi-devel-2.2.0-9.el7"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exempi");
}
