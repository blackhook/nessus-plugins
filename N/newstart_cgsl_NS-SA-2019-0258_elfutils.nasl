#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0258. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132468);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2018-16062",
    "CVE-2018-16402",
    "CVE-2018-16403",
    "CVE-2018-18310",
    "CVE-2018-18520",
    "CVE-2018-18521",
    "CVE-2019-7146",
    "CVE-2019-7148",
    "CVE-2019-7149",
    "CVE-2019-7150",
    "CVE-2019-7664",
    "CVE-2019-7665"
  );
  script_bugtraq_id(
    107134,
    108523,
    108806,
    108862
  );

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : elfutils Multiple Vulnerabilities (NS-SA-2019-0258)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has elfutils packages installed that are affected
by multiple vulnerabilities:

  - dwarf_getaranges in dwarf_getaranges.c in libdw in
    elfutils before 2018-08-18 allows remote attackers to
    cause a denial of service (heap-based buffer over-read)
    via a crafted file. (CVE-2018-16062)

  - libelf/elf_end.c in elfutils 0.173 allows remote
    attackers to cause a denial of service (double free and
    application crash) or possibly have unspecified other
    impact because it tries to decompress twice.
    (CVE-2018-16402)

  - libdw in elfutils 0.173 checks the end of the attributes
    list incorrectly in dwarf_getabbrev in dwarf_getabbrev.c
    and dwarf_hasattr in dwarf_hasattr.c, leading to a heap-
    based buffer over-read and an application crash.
    (CVE-2018-16403)

  - A heap-based buffer over-read was discovered in the
    function read_srclines in dwarf_getsrclines.c in libdw
    in elfutils 0.175. A crafted input can cause
    segmentation faults, leading to denial-of-service, as
    demonstrated by eu-nm. (CVE-2019-7149)

  - An issue was discovered in elfutils 0.175. A
    segmentation fault can occur in the function
    elf64_xlatetom in libelf/elf32_xlatetom.c, due to
    dwfl_segment_report_module not checking whether the dyn
    data read from a core file is truncated. A crafted input
    can cause a program crash, leading to denial-of-service,
    as demonstrated by eu-stack. (CVE-2019-7150)

  - An Invalid Memory Address Dereference exists in the
    function elf_end in libelf in elfutils through v0.174.
    Although eu-size is intended to support ar files inside
    ar files, handle_ar in size.c closes the outer ar file
    before handling all inner entries. The vulnerability
    allows attackers to cause a denial of service
    (application crash) with a crafted ELF file.
    (CVE-2018-18520)

  - Divide-by-zero vulnerabilities in the function
    arlib_add_symbols() in arlib.c in elfutils 0.174 allow
    remote attackers to cause a denial of service
    (application crash) with a crafted ELF file, as
    demonstrated by eu-ranlib, because a zero sh_entsize is
    mishandled. (CVE-2018-18521)

  - An invalid memory address dereference was discovered in
    dwfl_segment_report_module.c in libdwfl in elfutils
    through v0.174. The vulnerability allows attackers to
    cause a denial of service (application crash) with a
    crafted ELF file, as demonstrated by consider_notes.
    (CVE-2018-18310)

  - In elfutils 0.175, a heap-based buffer over-read was
    discovered in the function elf32_xlatetom in
    elf32_xlatetom.c in libelf. A crafted ELF input can
    cause a segmentation fault leading to denial of service
    (program crash) because ebl_core_note does not reject
    malformed core file notes. (CVE-2019-7665)

  - In elfutils 0.175, a negative-sized memcpy is attempted
    in elf_cvt_note in libelf/note_xlate.h because of an
    incorrect overflow check. Crafted elf input causes a
    segmentation fault, leading to denial of service
    (program crash). (CVE-2019-7664)

  - In elfutils 0.175, there is a buffer over-read in the
    ebl_object_note function in eblobjnote.c in libebl.
    Remote attackers could leverage this vulnerability to
    cause a denial-of-service via a crafted elf file, as
    demonstrated by eu-readelf. (CVE-2019-7146)

  - **DISPUTED** An attempted excessive memory allocation
    was discovered in the function read_long_names in
    elf_begin.c in libelf in elfutils 0.174. Remote
    attackers could leverage this vulnerability to cause a
    denial-of-service via crafted elf input, which leads to
    an out-of-memory exception. NOTE: The maintainers
    believe this is not a real issue, but instead a warning
    caused by ASAN because the allocation is big. By setting
    ASAN_OPTIONS=allocator_may_return_null=1 and running the
    reproducer, nothing happens. (CVE-2019-7148)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0258");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL elfutils packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16402");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");

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

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.05": [
    "elfutils-0.176-2.el7.cgslv5_5.0.1.gf2430b1.lite",
    "elfutils-debuginfo-0.176-2.el7.cgslv5_5.0.1.gf2430b1.lite",
    "elfutils-default-yama-scope-0.176-2.el7.cgslv5_5.0.1.gf2430b1.lite",
    "elfutils-devel-0.176-2.el7.cgslv5_5.0.1.gf2430b1.lite",
    "elfutils-devel-static-0.176-2.el7.cgslv5_5.0.1.gf2430b1.lite",
    "elfutils-libelf-0.176-2.el7.cgslv5_5.0.1.gf2430b1.lite",
    "elfutils-libelf-devel-0.176-2.el7.cgslv5_5.0.1.gf2430b1.lite",
    "elfutils-libelf-devel-static-0.176-2.el7.cgslv5_5.0.1.gf2430b1.lite",
    "elfutils-libelf-lang-0.176-2.el7.cgslv5_5.0.1.gf2430b1.lite",
    "elfutils-libs-0.176-2.el7.cgslv5_5.0.1.gf2430b1.lite"
  ],
  "CGSL MAIN 5.05": [
    "elfutils-0.176-2.el7.cgslv5_5",
    "elfutils-debuginfo-0.176-2.el7.cgslv5_5",
    "elfutils-default-yama-scope-0.176-2.el7.cgslv5_5",
    "elfutils-devel-0.176-2.el7.cgslv5_5",
    "elfutils-devel-static-0.176-2.el7.cgslv5_5",
    "elfutils-libelf-0.176-2.el7.cgslv5_5",
    "elfutils-libelf-devel-0.176-2.el7.cgslv5_5",
    "elfutils-libelf-devel-static-0.176-2.el7.cgslv5_5",
    "elfutils-libs-0.176-2.el7.cgslv5_5"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "elfutils");
}
