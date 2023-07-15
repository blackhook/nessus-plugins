#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131672);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2015-7995",
    "CVE-2016-1683",
    "CVE-2016-1684",
    "CVE-2016-4607",
    "CVE-2016-4608",
    "CVE-2016-4609",
    "CVE-2016-4610",
    "CVE-2016-4612",
    "CVE-2019-13117",
    "CVE-2019-13118",
    "CVE-2019-18197"
  );

  script_name(english:"EulerOS 2.0 SP2 : libxslt (EulerOS-SA-2019-2519)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libxslt packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - This C library allows to transform XML files into other
    XML files (or HTML, text, ...) using the standard XSLT
    stylesheet transformation mechanism. To use it you need
    to have a version of libxml2 i1/4z= 2.6.27 installed. The
    xsltproc command is a command line interface to the
    XSLT engine.Security Fix(es):In xsltCopyText in
    transform.c in libxslt 1.1.33, a pointer variable isn't
    reset under certain circumstances. If the relevant
    memory area happened to be freed and reused in a
    certain way, a bounds check could fail and memory
    outside a buffer could be written to, or uninitialized
    data could be disclosed.(CVE-2019-18197)The
    xsltStylePreCompute function in preproc.c in libxslt
    1.1.28 does not check if the parent node is an element,
    which allows attackers to cause a denial of service via
    a crafted XML file, related to a 'type confusion'
    issue.(CVE-2015-7995)numbers.c in libxslt before
    1.1.29, as used in Google Chrome before 51.0.2704.63,
    mishandles namespace nodes, which allows remote
    attackers to cause a denial of service (out-of-bounds
    heap memory access) or possibly have unspecified other
    impact via a crafted document.(CVE-2016-1683)numbers.c
    in libxslt before 1.1.29, as used in Google Chrome
    before 51.0.2704.63, mishandles the i format token for
    xsl:number data, which allows remote attackers to cause
    a denial of service (integer overflow or resource
    consumption) or possibly have unspecified other impact
    via a crafted document.(CVE-2016-1684)libxslt in Apple
    iOS before 9.3.3, OS X before 10.11.6, iTunes before
    12.4.2 on Windows, iCloud before 5.2.1 on Windows, tvOS
    before 9.2.2, and watchOS before 2.2.2 allows remote
    attackers to cause a denial of service (memory
    corruption) or possibly have unspecified other impact
    via unknown vectors, a different vulnerability than
    CVE-2016-4608, CVE-2016-4609, CVE-2016-4610, and
    CVE-2016-4612.(CVE-2016-4607)libxslt in Apple iOS
    before 9.3.3, OS X before 10.11.6, iTunes before 12.4.2
    on Windows, iCloud before 5.2.1 on Windows, tvOS before
    9.2.2, and watchOS before 2.2.2 allows remote attackers
    to cause a denial of service (memory corruption) or
    possibly have unspecified other impact via unknown
    vectors, a different vulnerability than CVE-2016-4607,
    CVE-2016-4609, CVE-2016-4610, and
    CVE-2016-4612.(CVE-2016-4608)libxslt in Apple iOS
    before 9.3.3, OS X before 10.11.6, iTunes before 12.4.2
    on Windows, iCloud before 5.2.1 on Windows, tvOS before
    9.2.2, and watchOS before 2.2.2 allows remote attackers
    to cause a denial of service (memory corruption) or
    possibly have unspecified other impact via unknown
    vectors, a different vulnerability than CVE-2016-4607,
    CVE-2016-4608, CVE-2016-4610, and
    CVE-2016-4612.(CVE-2016-4609)libxslt in Apple iOS
    before 9.3.3, OS X before 10.11.6, iTunes before 12.4.2
    on Windows, iCloud before 5.2.1 on Windows, tvOS before
    9.2.2, and watchOS before 2.2.2 allows remote attackers
    to cause a denial of service (memory corruption) or
    possibly have unspecified other impact via unknown
    vectors, a different vulnerability than CVE-2016-4607,
    CVE-2016-4608, CVE-2016-4609, and
    CVE-2016-4612.(CVE-2016-4610)** REJECT ** DO NOT USE
    THIS CANDIDATE NUMBER. ConsultIDs: CVE-2016-1683.
    Reason: This candidate is a reservation duplicate of
    CVE-2016-1683. Notes: All CVE users should reference
    CVE-2016-1683 instead of this candidate. All references
    and descriptions in this candidate have been removed to
    prevent accidental usage.(CVE-2016-4612)In numbers.c in
    libxslt 1.1.33, an xsl:number with certain format
    strings could lead to a uninitialized read in
    xsltNumberFormatInsertNumbers. This could allow an
    attacker to discern whether a byte on the stack
    contains the characters A, a, I, i, or 0, or any other
    character.(CVE-2019-13117)In numbers.c in libxslt
    1.1.33, a type holding grouping characters of an
    xsl:number instruction was too narrow and an invalid
    character/length combination could be passed to
    xsltNumberFormatDecimal, leading to a read of
    uninitialized stack data.(CVE-2019-13118)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2519
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f8d3fde");
  script_set_attribute(attribute:"solution", value:
"Update the affected libxslt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxslt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxslt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxslt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["libxslt-1.1.28-5.h6",
        "libxslt-devel-1.1.28-5.h6",
        "libxslt-python-1.1.28-5.h6"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxslt");
}
