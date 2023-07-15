#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135527);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-9482",
    "CVE-2016-5028",
    "CVE-2016-5029",
    "CVE-2016-5030",
    "CVE-2016-5031",
    "CVE-2016-5032",
    "CVE-2016-5033",
    "CVE-2016-5034",
    "CVE-2016-5035",
    "CVE-2016-5036",
    "CVE-2016-5037",
    "CVE-2016-5038",
    "CVE-2016-5039",
    "CVE-2016-5040",
    "CVE-2016-5041",
    "CVE-2016-5042",
    "CVE-2016-5043",
    "CVE-2016-5044",
    "CVE-2016-7510",
    "CVE-2016-8679",
    "CVE-2016-8680",
    "CVE-2016-8681"
  );
  script_bugtraq_id(
    71839
  );

  script_name(english:"EulerOS 2.0 SP3 : libdwarf (EulerOS-SA-2020-1398)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libdwarf package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Use-after-free vulnerability in dwarfdump in libdwarf
    20130126 through 20140805 might allow remote attackers
    to cause a denial of service (program crash) via a
    crafted ELF file.(CVE-2014-9482)

  - The print_frame_inst_bytes function in libdwarf before
    20160923 allows remote attackers to cause a denial of
    service (NULL pointer dereference) via an object file
    with empty bss-like sections.(CVE-2016-5028)

  - The create_fullest_file_path function in libdwarf
    before 20160923 allows remote attackers to cause a
    denial of service (NULL pointer dereference) via a
    crafted dwarf file.(CVE-2016-5029)

  - The _dwarf_calculate_info_section_end_ptr function in
    libdwarf before 20160923 allows remote attackers to
    cause a denial of service (NULL pointer dereference)
    via a crafted file.(CVE-2016-5030)

  - The print_frame_inst_bytes function in libdwarf before
    20160923 allows remote attackers to cause a denial of
    service (out-of-bounds read) via a crafted
    file.(CVE-2016-5031)

  - The dwarf_get_xu_hash_entry function in libdwarf before
    20160923 allows remote attackers to cause a denial of
    service (crash) via a crafted file.(CVE-2016-5032)

  - The print_exprloc_content function in libdwarf before
    20160923 allows remote attackers to cause a denial of
    service (out-of-bounds read) via a crafted
    file.(CVE-2016-5033)

  - dwarf_elf_access.c in libdwarf before 20160923 allows
    remote attackers to cause a denial of service
    (out-of-bounds write) via a crafted file, related to
    relocation records.(CVE-2016-5034)

  - The _dwarf_read_line_table_header function in
    dwarf_line_table_reader.c in libdwarf before 20160923
    allows remote attackers to cause a denial of service
    (out-of-bounds read) via a crafted file.(CVE-2016-5035)

  - The dump_block function in print_sections.c in libdwarf
    before 20160923 allows remote attackers to cause a
    denial of service (out-of-bounds read) via crafted
    frame data.(CVE-2016-5036)

  - The _dwarf_load_section function in libdwarf before
    20160923 allows remote attackers to cause a denial of
    service (NULL pointer dereference) via a crafted
    file.(CVE-2016-5037)

  - The dwarf_get_macro_startend_file function in
    dwarf_macro5.c in libdwarf before 20160923 allows
    remote attackers to cause a denial of service
    (out-of-bounds read) via a crafted string offset for
    .debug_str.(CVE-2016-5038)

  - The get_attr_value function in libdwarf before 20160923
    allows remote attackers to cause a denial of service
    (out-of-bounds read) via a crafted object with all-bits
    on.(CVE-2016-5039)

  - libdwarf before 20160923 allows remote attackers to
    cause a denial of service (out-of-bounds read and
    crash) via a large length value in a compilation unit
    header.(CVE-2016-5040)

  - dwarf_macro5.c in libdwarf before 20160923 allows
    remote attackers to cause a denial of service (NULL
    pointer dereference) via a debugging information entry
    using DWARF5 and without a DW_AT_name.(CVE-2016-5041)

  - The dwarf_get_aranges_list function in libdwarf before
    20160923 allows remote attackers to cause a denial of
    service (infinite loop and crash) via a crafted DWARF
    section.(CVE-2016-5042)

  - The dwarf_dealloc function in libdwarf before 20160923
    allows remote attackers to cause a denial of service
    (out-of-bounds read and crash) via a crafted DWARF
    section.(CVE-2016-5043)

  - The WRITE_UNALIGNED function in dwarf_elf_access.c in
    libdwarf before 20160923 allows remote attackers to
    cause a denial of service (out-of-bounds write and
    crash) via a crafted DWARF section.(CVE-2016-5044)

  - The read_line_table_program function in
    dwarf_line_table_reader_common.c in libdwarf before
    20160923 allows remote attackers to cause a denial of
    service (out-of-bounds read) via crafted
    input.(CVE-2016-7510)

  - The _dwarf_get_size_of_val function in
    libdwarf/dwarf_util.c in Libdwarf before 20161124
    allows remote attackers to cause a denial of service
    (out-of-bounds read) by calling the dwarfdump command
    on a crafted file.(CVE-2016-8679)

  - The _dwarf_get_abbrev_for_code function in dwarf_util.c
    in libdwarf 20161001 and earlier allows remote
    attackers to cause a denial of service (out-of-bounds
    read) by calling the dwarfdump command on a crafted
    file.(CVE-2016-8680)

  - The _dwarf_get_abbrev_for_code function in dwarf_util.c
    in libdwarf 20161001 and earlier allows remote
    attackers to cause a denial of service (out-of-bounds
    read) by calling the dwarfdump command on a crafted
    file.(CVE-2016-8681)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1398
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d6a13ba");
  script_set_attribute(attribute:"solution", value:
"Update the affected libdwarf packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libdwarf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["libdwarf-20170416-1"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libdwarf");
}
