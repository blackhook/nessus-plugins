#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154372);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id(
    "CVE-2021-29457",
    "CVE-2021-29458",
    "CVE-2021-29473",
    "CVE-2021-31291",
    "CVE-2021-31292",
    "CVE-2021-32617"
  );

  script_name(english:"EulerOS 2.0 SP3 : exiv2 (EulerOS-SA-2021-2579)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the exiv2 package installed, the EulerOS installation on the remote host is affected by the
following vulnerabilities :

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
    as insert. The bug is fixed in version v0.27.4. (CVE-2021-29458)

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

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2021-29457. Reason: This candidate is a
    duplicate of CVE-2021-29457. Notes: All CVE users should reference CVE-2021-29457 instead of this
    candidate. All references and descriptions in this candidate have been removed to prevent accidental
    usage. (CVE-2021-31291)

  - An integer overflow in CrwMap::encode0x1810 of Exiv2 0.27.3 allows attackers to trigger a heap-based
    buffer overflow and cause a denial of service (DOS) via crafted metadata. (CVE-2021-31292)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An inefficient algorithm (quadratic complexity) was found in Exiv2 versions v0.27.3 and
    earlier. The inefficient algorithm is triggered when Exiv2 is used to write metadata into a crafted image
    file. An attacker could potentially exploit the vulnerability to cause a denial of service, if they can
    trick the victim into running Exiv2 on a crafted image file. The bug is fixed in version v0.27.4. Note
    that this bug is only triggered when _writing_ the metadata, which is a less frequently used Exiv2
    operation than _reading_ the metadata. For example, to trigger the bug in the Exiv2 command-line
    application, you need to add an extra command-line argument such as `rm`. (CVE-2021-32617)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2579
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8fa50dac");
  script_set_attribute(attribute:"solution", value:
"Update the affected exiv2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31291");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:exiv2-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
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

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "exiv2-libs-0.23-6.h13"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exiv2");
}
