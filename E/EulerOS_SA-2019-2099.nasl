#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130808);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-1000876",
    "CVE-2018-18309",
    "CVE-2018-18605",
    "CVE-2018-18606",
    "CVE-2018-18607",
    "CVE-2018-20002",
    "CVE-2019-1010180",
    "CVE-2019-14444"
  );

  script_name(english:"EulerOS 2.0 SP8 : binutils (EulerOS-SA-2019-2099)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the binutils packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.31. An invalid memory address dereference
    was discovered in read_reloc in reloc.c. The
    vulnerability causes a segmentation fault and
    application crash, which leads to denial of service, as
    demonstrated by objdump, because of missing
    _bfd_clear_contents bounds checking.(CVE-2018-18309)

  - A heap-based buffer over-read issue was discovered in
    the function sec_merge_hash_lookup in merge.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.31, because
    _bfd_add_merge_section mishandles section merges when
    size is not a multiple of entsize. A specially crafted
    ELF allows remote attackers to cause a denial of
    service, as demonstrated by ld.(CVE-2018-18605)

  - An issue was discovered in elf_link_input_bfd in
    elflink.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.31.
    There is a NULL pointer dereference in
    elf_link_input_bfd when used for finding STT_TLS
    symbols without any TLS section. A specially crafted
    ELF allows remote attackers to cause a denial of
    service, as demonstrated by ld.(CVE-2018-18607)

  - An issue was discovered in the merge_strings function
    in merge.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.31.
    There is a NULL pointer dereference in
    _bfd_add_merge_section when attempting to merge
    sections with large alignments. A specially crafted ELF
    allows remote attackers to cause a denial of service,
    as demonstrated by ld.(CVE-2018-18606)

  - binutils version 2.32 and earlier contains a Integer
    Overflow vulnerability in objdump,
    bfd_get_dynamic_reloc_upper_bound,bfd_canonicalize_dyna
    mic_reloc that can result in Integer overflow trigger
    heap overflow. Successful exploitation allows execution
    of arbitrary code.. This attack appear to be
    exploitable via Local. This vulnerability appears to
    have been fixed in after commit
    3a551c7a1b80fca579461774860574eabfd7f18f.(CVE-2018-1000
    876)

  - The _bfd_generic_read_minisymbols function in syms.c in
    the Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.31, has a memory leak
    via a crafted ELF file, leading to a denial of service
    (memory consumption), as demonstrated by
    nm.(CVE-2018-20002)

  - GNU gdb All versions is affected by: Buffer Overflow -
    Out of bound memory access. The impact is: Deny of
    Service, Memory Disclosure, and Possible Code
    Execution. The component is: The main gdb module. The
    attack vector is: Open an ELF for debugging. The fixed
    version is: Not fixed yet.(CVE-2019-1010180)

  - apply_relocations in readelf.c in GNU Binutils 2.32
    contains an integer overflow that allows attackers to
    trigger a write access violation (in
    byte_put_little_endian function in elfcomm.c) via an
    ELF file, as demonstrated by readelf.(CVE-2019-14444)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2099
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?225bde2c");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["binutils-2.31.1-13.h7.eulerosv2r8",
        "binutils-devel-2.31.1-13.h7.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
