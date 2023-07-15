#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124924);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2011-2501",
    "CVE-2011-2690",
    "CVE-2011-2691",
    "CVE-2011-2692",
    "CVE-2011-3026",
    "CVE-2011-3048",
    "CVE-2015-7981",
    "CVE-2015-8472",
    "CVE-2015-8540"
  );
  script_bugtraq_id(
    48474,
    48618,
    48660,
    52031,
    52049,
    52830
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : libpng (EulerOS-SA-2019-1421)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libpng package installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - The png_set_text_2 function in pngset.c in libpng 1.0.x
    before 1.0.59, 1.2.x before 1.2.49, 1.4.x before
    1.4.11, and 1.5.x before 1.5.10 allows remote attackers
    to cause a denial of service (crash) or execute
    arbitrary code via a crafted text chunk in a PNG image
    file, which triggers a memory allocation failure that
    is not properly handled, leading to a heap-based buffer
    overflow.(CVE-2011-3048)

  - The png_handle_sCAL function in pngrutil.c in libpng
    1.0.x before 1.0.55, 1.2.x before 1.2.45, 1.4.x before
    1.4.8, and 1.5.x before 1.5.4 does not properly handle
    invalid sCAL chunks, which allows remote attackers to
    cause a denial of service (memory corruption and
    application crash) or possibly have unspecified other
    impact via a crafted PNG image that triggers the
    reading of uninitialized memory.(CVE-2011-2692)

  - It was discovered that the png_get_PLTE() and
    png_set_PLTE() functions of libpng did not correctly
    calculate the maximum palette sizes for bit depths of
    less than 8. In case an application tried to use these
    functions in combination with properly calculated
    palette sizes, this could lead to a buffer overflow or
    out-of-bounds reads. An attacker could exploit this to
    cause a crash or potentially execute arbitrary code by
    tricking an unsuspecting user into processing a
    specially crafted PNG image. However, the exact impact
    is dependent on the application using the
    library.(CVE-2015-8472)

  - The png_err function in pngerror.c in libpng 1.0.x
    before 1.0.55, 1.2.x before 1.2.45, 1.4.x before 1.4.8,
    and 1.5.x before 1.5.4 makes a function call using a
    NULL pointer argument instead of an empty-string
    argument, which allows remote attackers to cause a
    denial of service (application crash) via a crafted PNG
    image.(CVE-2011-2691)

  - Integer underflow in the png_check_keyword function in
    pngwutil.c in libpng 0.90 through 0.99, 1.0.x before
    1.0.66, 1.1.x and 1.2.x before 1.2.56, 1.3.x and 1.4.x
    before 1.4.19, and 1.5.x before 1.5.26 allows remote
    attackers to have unspecified impact via a space
    character as a keyword in a PNG image, which triggers
    an out-of-bounds read.(CVE-2015-8540)

  - Integer overflow in libpng, as used in Google Chrome
    before 17.0.963.56, allows remote attackers to cause a
    denial of service or possibly have unspecified other
    impact via unknown vectors that trigger an integer
    truncation.(CVE-2011-3026)

  - An array-indexing error was discovered in the
    png_convert_to_rfc1123() function of libpng. An
    attacker could possibly use this flaw to cause an
    out-of-bounds read by tricking an unsuspecting user
    into processing a specially crafted PNG
    image.(CVE-2015-7981)

  - Buffer overflow in libpng 1.0.x before 1.0.55, 1.2.x
    before 1.2.45, 1.4.x before 1.4.8, and 1.5.x before
    1.5.4, when used by an application that calls the
    png_rgb_to_gray function but not the png_set_expand
    function, allows remote attackers to overwrite memory
    with an arbitrary amount of data, and possibly have
    unspecified other impact, via a crafted PNG
    image.(CVE-2011-2690)

  - The png_format_buffer function in pngerror.c in libpng
    1.0.x before 1.0.55, 1.2.x before 1.2.45, 1.4.x before
    1.4.8, and 1.5.x before 1.5.4 allows remote attackers
    to cause a denial of service (application crash) via a
    crafted PNG image that triggers an out-of-bounds read
    during the copying of error-message data. NOTE: this
    vulnerability exists because of a CVE-2004-0421
    regression. NOTE: this is called an off-by-one error by
    some sources.(CVE-2011-2501)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1421
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1d8567b");
  script_set_attribute(attribute:"solution", value:
"Update the affected libpng packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libpng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libpng-1.5.13-7.1.h2.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng");
}
