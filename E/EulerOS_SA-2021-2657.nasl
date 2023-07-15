#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155288);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/11");

  script_cve_id(
    "CVE-2020-18771",
    "CVE-2021-32815",
    "CVE-2021-34334",
    "CVE-2021-34335",
    "CVE-2021-37615",
    "CVE-2021-37616",
    "CVE-2021-37620",
    "CVE-2021-37622",
    "CVE-2021-37623"
  );

  script_name(english:"EulerOS 2.0 SP5 : exiv2 (EulerOS-SA-2021-2657)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the exiv2 package installed, the EulerOS installation on the remote host is affected by the
following vulnerabilities :

  - Exiv2 0.27.99.0 has a global buffer over-read in Exiv2::Internal::Nikon1MakerNote::print0x0088 in
    nikonmn_int.cpp which can result in an information leak. (CVE-2020-18771)

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

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An infinite loop is triggered when Exiv2 is used to read the metadata of a crafted image
    file. An attacker could potentially exploit the vulnerability to cause a denial of service, if they can
    trick the victim into running Exiv2 on a crafted image file. The bug is fixed in version v0.27.5.
    (CVE-2021-34334)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. A floating point exception (FPE) due to an integer divide by zero was found in Exiv2
    versions v0.27.4 and earlier. The FPE is triggered when Exiv2 is used to print the metadata of a crafted
    image file. An attacker could potentially exploit the vulnerability to cause a denial of service, if they
    can trick the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when
    printing the interpreted (translated) data, which is a less frequently used Exiv2 operation that requires
    an extra command line option (`-p t` or `-P t`). The bug is fixed in version v0.27.5. (CVE-2021-34335)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. A null pointer dereference was found in Exiv2 versions v0.27.4 and earlier. The null
    pointer dereference is triggered when Exiv2 is used to print the metadata of a crafted image file. An
    attacker could potentially exploit the vulnerability to cause a denial of service, if they can trick the
    victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when printing the
    interpreted (translated) data, which is a less frequently used Exiv2 operation that requires an extra
    command line option (`-p t` or `-P t`). The bug is fixed in version v0.27.5. (CVE-2021-37615,
    CVE-2021-37616)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in Exiv2 versions v0.27.4 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to read the metadata of a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial of service, if they can trick the victim into
    running Exiv2 on a crafted image file. The bug is fixed in version v0.27.5. (CVE-2021-37620)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An infinite loop was found in Exiv2 versions v0.27.4 and earlier. The infinite loop is
    triggered when Exiv2 is used to modify the metadata of a crafted image file. An attacker could potentially
    exploit the vulnerability to cause a denial of service, if they can trick the victim into running Exiv2 on
    a crafted image file. Note that this bug is only triggered when deleting the IPTC data, which is a less
    frequently used Exiv2 operation that requires an extra command line option (`-d I rm`). The bug is fixed
    in version v0.27.5. (CVE-2021-37622, CVE-2021-37623)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2657
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79ab2360");
  script_set_attribute(attribute:"solution", value:
"Update the affected exiv2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-18771");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

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
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "exiv2-libs-0.26-3.h17.eulerosv2r7"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
