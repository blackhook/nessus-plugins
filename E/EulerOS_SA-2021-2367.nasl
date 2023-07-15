#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153280);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/16");

  script_cve_id(
    "CVE-2018-11531",
    "CVE-2018-16336",
    "CVE-2018-19607",
    "CVE-2019-17402",
    "CVE-2021-29458",
    "CVE-2021-29473",
    "CVE-2021-32617"
  );

  script_name(english:"EulerOS 2.0 SP2 : exiv2 (EulerOS-SA-2021-2367)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the exiv2 package installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - Exiv2 is a command-line utility and C++ library for
    reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in
    Exiv2 versions v0.27.3 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to write metadata
    into a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial
    of service by crashing Exiv2, if they can trick the
    victim into running Exiv2 on a crafted image file. Note
    that this bug is only triggered when writing the
    metadata, which is a less frequently used Exiv2
    operation than reading the metadata. For example, to
    trigger the bug in the Exiv2 command-line application,
    you need to add an extra command-line argument such as
    insert.(CVE-2021-29458)

  - Exiv2 is a C++ library and a command-line utility to
    read, write, delete and modify Exif, IPTC, XMP and ICC
    image metadata. An out-of-bounds read was found in
    Exiv2 versions v0.27.3 and earlier. Exiv2 is a
    command-line utility and C++ library for reading,
    writing, deleting, and modifying the metadata of image
    files. The out-of-bounds read is triggered when Exiv2
    is used to write metadata into a crafted image file. An
    attacker could potentially exploit the vulnerability to
    cause a denial of service by crashing Exiv2, if they
    can trick the victim into running Exiv2 on a crafted
    image file. Note that this bug is only triggered when
    writing the metadata, which is a less frequently used
    Exiv2 operation than reading the metadata. For example,
    to trigger the bug in the Exiv2 command-line
    application, you need to add an extra command-line
    argument such as `insert`.(CVE-2021-29473)

  - Exiv2 is a command-line utility and C++ library for
    reading, writing, deleting, and modifying the metadata
    of image files. An inefficient algorithm (quadratic
    complexity) was found in Exiv2 versions v0.27.3 and
    earlier. The inefficient algorithm is triggered when
    Exiv2 is used to write metadata into a crafted image
    file. An attacker could potentially exploit the
    vulnerability to cause a denial of service, if they can
    trick the victim into running Exiv2 on a crafted image
    file.(CVE-2021-32617)

  - Exiv2 0.27.2 allows attackers to trigger a crash in
    Exiv2::getULong in types.cpp when called from
    Exiv2::Internal::CiffDirectory::readDirectory in
    crwimage_int.cpp, because there is no validation of the
    relationship of the total size to the offset and
    size.(CVE-2019-17402)

  - Exiv2::Internal::PngChunk::parseTXTChunk in Exiv2 v0.26
    allows remote attackers to cause a denial of service
    (heap-based buffer over-read) via a crafted image file,
    a different vulnerability than
    CVE-2018-10999.(CVE-2018-16336)

  - Exiv2::isoSpeed in easyaccess.cpp in Exiv2 v0.27-RC2
    allows remote attackers to cause a denial of service
    (NULL pointer dereference and application crash) via a
    crafted file.(CVE-2018-19607)

  - Exiv2 0.26 has a heap-based buffer overflow in getData
    in preview.cpp.(CVE-2018-11531)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2367
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5015edaf");
  script_set_attribute(attribute:"solution", value:
"Update the affected exiv2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11531");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:exiv2-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["exiv2-libs-0.23-6.h8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exiv2");
}
