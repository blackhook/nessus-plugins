#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135150);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-18483",
    "CVE-2018-20657",
    "CVE-2019-14250",
    "CVE-2019-9070",
    "CVE-2019-9071",
    "CVE-2019-9074",
    "CVE-2019-9076"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : binutils (EulerOS-SA-2020-1363)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the binutils package installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - An issue was discovered in GNU libiberty, as
    distributed in GNU Binutils 2.32.
    simple_object_elf_match in simple-object-elf.c does not
    check for a zero shstrndx value, leading to an integer
    overflow and resultant heap-based buffer
    overflow.(CVE-2019-14250)

  - An issue was discovered in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. It is an attempted excessive memory
    allocation in elf_read_notes in elf.c.(CVE-2019-9076)

  - An issue was discovered in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. It is an out-of-bounds read leading to a
    SEGV in bfd_getl32 in libbfd.c, when called from
    pex64_get_runtime_function in
    pei-x86_64.c.(CVE-2019-9074)

  - An issue was discovered in GNU libiberty, as
    distributed in GNU Binutils 2.32. It is a stack
    consumption issue in d_count_templates_scopes in
    cp-demangle.c after many recursive
    calls.(CVE-2019-9071)

  - An issue was discovered in GNU libiberty, as
    distributed in GNU Binutils 2.32. It is a heap-based
    buffer over-read in d_expression_1 in cp-demangle.c
    after many recursive calls.(CVE-2019-9070)

  - The demangle_template function in cplus-dem.c in GNU
    libiberty, as distributed in GNU Binutils 2.31.1, has a
    memory leak via a crafted string, leading to a denial
    of service (memory consumption), as demonstrated by
    cxxfilt, a related issue to
    CVE-2018-12698.(CVE-2018-20657)

  - The get_count function in cplus-dem.c in GNU libiberty,
    as distributed in GNU Binutils 2.31, allows remote
    attackers to cause a denial of service (malloc called
    with the result of an integer-overflowing calculation)
    or possibly have unspecified other impact via a crafted
    string, as demonstrated by c++filt.(CVE-2018-18483)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1363
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e3462dc");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:binutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["binutils-2.31.1-13.h16.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils");
}
