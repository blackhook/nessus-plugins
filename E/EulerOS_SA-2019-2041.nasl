#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129234);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-12799",
    "CVE-2017-14130",
    "CVE-2017-15996",
    "CVE-2017-7302",
    "CVE-2017-8396",
    "CVE-2017-8397",
    "CVE-2017-8398",
    "CVE-2017-9040",
    "CVE-2017-9042",
    "CVE-2017-9742",
    "CVE-2017-9744",
    "CVE-2017-9746",
    "CVE-2017-9747",
    "CVE-2017-9748",
    "CVE-2017-9749",
    "CVE-2017-9752",
    "CVE-2017-9753",
    "CVE-2017-9754",
    "CVE-2017-9756",
    "CVE-2018-12697",
    "CVE-2018-17360",
    "CVE-2019-1010204",
    "CVE-2019-9075"
  );

  script_name(english:"EulerOS 2.0 SP3 : binutils (EulerOS-SA-2019-2041)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the binutils packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - GNU binutils gold gold v1.11-v1.16 (GNU binutils
    v2.21-v2.31.1) is affected by: Improper Input
    Validation, Signed/Unsigned Comparison, Out-of-bounds
    Read. The impact is: Denial of service. The component
    is: gold/fileread.cc:497, elfcpp/elfcpp_file.h:644. The
    attack vector is: An ELF file with an invalid e_shoff
    header field must be opened.(CVE-2019-1010204)

  - The _bfd_elf_parse_attributes function in elf-attrs.c
    in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.29, allows
    remote attackers to cause a denial of service
    (_bfd_elf_attr_strdup heap-based buffer over-read and
    application crash) via a crafted ELF
    file.(CVE-2017-14130)

  - The aarch64_ext_ldst_reglist function in
    opcodes/aarch64-dis.c in GNU Binutils 2.28 allows
    remote attackers to cause a denial of service (buffer
    overflow and application crash) or possibly have
    unspecified other impact via a crafted binary file, as
    demonstrated by mishandling of this file during
    'objdump -D' execution.(CVE-2017-9756)

  - The process_otr function in bfd/versados.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.28, does not validate a
    certain offset, which allows remote attackers to cause
    a denial of service (buffer overflow and application
    crash) or possibly have unspecified other impact via a
    crafted binary file, as demonstrated by mishandling of
    this file during 'objdump -D' execution.(CVE-2017-9754)

  - The versados_mkobject function in bfd/versados.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.28, does not initialize a
    certain data structure, which allows remote attackers
    to cause a denial of service (buffer overflow and
    application crash) or possibly have unspecified other
    impact via a crafted binary file, as demonstrated by
    mishandling of this file during 'objdump -D'
    execution.(CVE-2017-9753)

  - bfd/vms-alpha.c in the Binary File Descriptor (BFD)
    library (aka libbfd), as distributed in GNU Binutils
    2.28, allows remote attackers to cause a denial of
    service (buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    binary file, as demonstrated by mishandling of this
    file in the _bfd_vms_get_value and _bfd_vms_slurp_etir
    functions during 'objdump -D' execution.(CVE-2017-9752)

  - The *regs* macros in opcodes/bfin-dis.c in GNU Binutils
    2.28 allow remote attackers to cause a denial of
    service (buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    binary file, as demonstrated by mishandling of this
    file during 'objdump -D' execution.(CVE-2017-9749)

  - The ieee_object_p function in bfd/ieee.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.28, might allow remote
    attackers to cause a denial of service (buffer overflow
    and application crash) or possibly have unspecified
    other impact via a crafted binary file, as demonstrated
    by mishandling of this file during 'objdump -D'
    execution. NOTE: this may be related to a compiler
    bug.(CVE-2017-9748)

  - The ieee_archive_p function in bfd/ieee.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.28, might allow remote
    attackers to cause a denial of service (buffer overflow
    and application crash) or possibly have unspecified
    other impact via a crafted binary file, as demonstrated
    by mishandling of this file during 'objdump -D'
    execution. NOTE: this may be related to a compiler
    bug.(CVE-2017-9747)

  - The disassemble_bytes function in objdump.c in GNU
    Binutils 2.28 allows remote attackers to cause a denial
    of service (buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    binary file, as demonstrated by mishandling of rae
    insns printing for this file during 'objdump -D'
    execution.(CVE-2017-9746)

  - The sh_elf_set_mach_from_flags function in
    bfd/elf32-sh.c in the Binary File Descriptor (BFD)
    library (aka libbfd), as distributed in GNU Binutils
    2.28, allows remote attackers to cause a denial of
    service (buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    binary file, as demonstrated by mishandling of this
    file during 'objdump -D' execution.(CVE-2017-9744)

  - The score_opcodes function in opcodes/score7-dis.c in
    GNU Binutils 2.28 allows remote attackers to cause a
    denial of service (buffer overflow and application
    crash) or possibly have unspecified other impact via a
    crafted binary file, as demonstrated by mishandling of
    this file during 'objdump -D' execution.(CVE-2017-9742)

  - readelf.c in GNU Binutils 2017-04-12 has a 'cannot be
    represented in type long' issue, which might allow
    remote attackers to cause a denial of service
    (application crash) or possibly have unspecified other
    impact via a crafted ELF file.(CVE-2017-9042)

  - GNU Binutils 2017-04-03 allows remote attackers to
    cause a denial of service (NULL pointer dereference and
    application crash), related to the
    process_mips_specific function in readelf.c, via a
    crafted ELF file that triggers a large
    memory-allocation attempt.(CVE-2017-9040)

  - The elf_read_notesfunction in bfd/elf.c in GNU Binutils
    2.29 allows remote attackers to cause a denial of
    service (buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    binary file.(CVE-2017-12799)

  - dwarf.c in GNU Binutils 2.28 is vulnerable to an
    invalid read of size 1 during dumping of debug
    information from a corrupt binary. This vulnerability
    causes programs that conduct an analysis of binary
    programs, such as objdump and readelf, to
    crash.(CVE-2017-8398)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, is vulnerable to
    an invalid read of size 1 and an invalid write of size
    1 during processing of a corrupt binary containing
    reloc(s) with negative addresses. This vulnerability
    causes programs that conduct an analysis of binary
    programs using the libbfd library, such as objdump, to
    crash.(CVE-2017-8397)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, is vulnerable to
    an invalid read of size 1 because the existing reloc
    offset range tests didn't catch small negative offsets
    less than the size of the reloc field. This
    vulnerability causes programs that conduct an analysis
    of binary programs using the libbfd library, such as
    objdump, to crash.(CVE-2017-8396)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, has a
    swap_std_reloc_out function in bfd/aoutx.h that is
    vulnerable to an invalid read (of size 4) because of
    missing checks for relocs that could not be recognised.
    This vulnerability causes Binutils utilities like strip
    to crash.(CVE-2017-7302)

  - A NULL pointer dereference (aka SEGV on unknown address
    0x000000000000) was discovered in
    work_stuff_copy_to_from in cplus-dem.c in GNU
    libiberty, as distributed in GNU Binutils 2.30. This
    can occur during execution of objdump.(CVE-2018-12697)

  - An issue was discovered in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. It is a heap-based buffer overflow in
    _bfd_archive_64_bit_slurp_armap in
    archive64.c.(CVE-2019-9075)

  - elfcomm.c in readelf in GNU Binutils 2.29 allows remote
    attackers to cause a denial of service (excessive
    memory allocation) or possibly have unspecified other
    impact via a crafted ELF file that triggers a 'buffer
    overflow on fuzzed archive header,' related to an
    uninitialized variable, an improper conditional jump,
    and the get_archive_member_name,
    process_archive_index_and_symbols, and setup_archive
    functions.(CVE-2017-15996)

  - An issue was discovered in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.31. a heap-based buffer over-read in
    bfd_getl32 in libbfd.c allows an attacker to cause a
    denial of service through a crafted PE file. This
    vulnerability can be triggered by the executable
    objdump.(CVE-2018-17360)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2041
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ea3cc85");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:binutils-devel");
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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["binutils-2.25.1-22.base.h27",
        "binutils-devel-2.25.1-22.base.h27"];

foreach (pkg in pkgs)
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils");
}
