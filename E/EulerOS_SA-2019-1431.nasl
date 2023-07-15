#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124934);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id(
    "CVE-2014-8484",
    "CVE-2014-8485",
    "CVE-2014-8501",
    "CVE-2014-8502",
    "CVE-2014-8503",
    "CVE-2014-8504",
    "CVE-2014-8737",
    "CVE-2014-8738",
    "CVE-2017-15020",
    "CVE-2017-16826",
    "CVE-2017-16827",
    "CVE-2017-16828",
    "CVE-2017-16831",
    "CVE-2018-19932",
    "CVE-2018-7208",
    "CVE-2018-7568",
    "CVE-2018-7569",
    "CVE-2018-7642",
    "CVE-2018-7643",
    "CVE-2018-8945"
  );
  script_bugtraq_id(
    70714,
    70741,
    70761,
    70866,
    70868,
    70869,
    70908,
    71083
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : binutils (EulerOS-SA-2019-1431)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the binutils package installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - An integer wraparound has been discovered in the Binary
    File Descriptor (BFD) library distributed in GNU
    Binutils up to version 2.30. An attacker could cause a
    crash by providing an ELF file with corrupted DWARF
    debug information.(CVE-2018-7568)

  - A stack-based buffer overflow flaw was found in the way
    various binutils utilities processed certain files. If
    a user were tricked into processing a specially crafted
    file, it could cause the utility used to process that
    file to crash or, potentially, execute arbitrary code
    with the privileges of the user running that
    utility.(CVE-2014-8501)

  - The coff_slurp_line_table function in coffcode.h in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29.1, allows remote
    attackers to cause a denial of service (invalid memory
    access and application crash) or possibly have
    unspecified other impact via a crafted PE
    file.(CVE-2017-16826)

  - It was found that the fix for the CVE-2014-8485 issue
    was incomplete: a heap-based buffer overflow in the
    objdump utility could cause it to crash or,
    potentially, execute arbitrary code with the privileges
    of the user running objdump when processing specially
    crafted files.(CVE-2014-8502)

  - A directory traversal flaw was found in the strip and
    objcopy utilities. A specially crafted file could cause
    strip or objdump to overwrite an arbitrary file
    writable by the user running either of these
    utilities.(CVE-2014-8737)

  - The bfd_section_from_shdr function in elf.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, allows remote
    attackers to cause a denial of service (segmentation
    fault) via a large attribute section.(CVE-2018-8945)

  - In the coff_pointerize_aux function in coffgen.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, an index is not
    validated, which allows remote attackers to cause a
    denial of service (segmentation fault) or possibly have
    unspecified other impact via a crafted file, as
    demonstrated by objcopy of a COFF
    object.(CVE-2018-7208)

  - dwarf1.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.29,
    mishandles pointers, which allows remote attackers to
    cause a denial of service (application crash) or
    possibly have unspecified other impact via a crafted
    ELF file, related to parse_die and parse_line_table, as
    demonstrated by a parse_die heap-based buffer
    over-read.(CVE-2017-15020)

  - A buffer overflow flaw was found in the way various
    binutils utilities processed certain files. If a user
    were tricked into processing a specially crafted file,
    it could cause the utility used to process that file to
    crash or, potentially, execute arbitrary code with the
    privileges of the user running that
    utility.(CVE-2014-8485)

  - An integer overflow flaw was found in the way the
    strings utility processed certain files. If a user were
    tricked into running the strings utility on a specially
    crafted file, it could cause the strings executable to
    crash.(CVE-2014-8484)

  - A heap-based buffer overflow flaw was found in the way
    certain binutils utilities processed archive files. If
    a user were tricked into processing a specially crafted
    archive file, it could cause the utility used to
    process that archive to crash or, potentially, execute
    arbitrary code with the privileges of the user running
    that utility.(CVE-2014-8738)

  - The swap_std_reloc_in function in aoutx.h in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, allows remote
    attackers to cause a denial of service
    (aout_32_swap_std_reloc_out NULL pointer dereference
    and application crash) via a crafted ELF file, as
    demonstrated by objcopy.(CVE-2018-7642)

  - The display_debug_frames function in dwarf.c in GNU
    Binutils 2.29.1 allows remote attackers to cause a
    denial of service (integer overflow and heap-based
    buffer over-read, and application crash) or possibly
    have unspecified other impact via a crafted ELF file,
    related to print_debug_frame.(CVE-2017-16828)

  - A stack-based buffer overflow flaw was found in the
    SREC parser of the libbfd library. A specially crafted
    file could cause an application using the libbfd
    library to crash or, potentially, execute arbitrary
    code with the privileges of the user running that
    application.(CVE-2014-8504)

  - An integer wraparound has been discovered in the Binary
    File Descriptor (BFD) library distributed in GNU
    Binutils up to version 2.30. An attacker could cause a
    crash by providing an ELF file with corrupted DWARF
    debug information.(CVE-2018-7569)

  - A stack-based buffer overflow flaw was found in the way
    objdump processed IHEX files. A specially crafted IHEX
    file could cause objdump to crash or, potentially,
    execute arbitrary code with the privileges of the user
    running objdump.(CVE-2014-8503)

  - coffgen.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.29.1,
    does not validate the symbol count, which allows remote
    attackers to cause a denial of service (integer
    overflow and application crash, or excessive memory
    allocation) or possibly have unspecified other impact
    via a crafted PE file.(CVE-2017-16831)

  - The aout_get_external_symbols function in aoutx.h in
    the Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.29.1, allows remote
    attackers to cause a denial of service (slurp_symtab
    invalid free and application crash) or possibly have
    unspecified other impact via a crafted ELF
    file.(CVE-2017-16827)

  - The display_debug_ranges function in dwarf.c in GNU
    Binutils 2.30 allows remote attackers to cause a denial
    of service (integer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    ELF file, as demonstrated by objdump.(CVE-2018-7643)

  - An issue was discovered in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU
    Binutils through 2.31. There is an integer overflow and
    infinite loop caused by the IS_CONTAINED_BY_LMA macro
    in elf.c.(CVE-2018-19932)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1431
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2de8da5b");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:binutils");
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

pkgs = ["binutils-2.27-28.base.1.h15"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils");
}
