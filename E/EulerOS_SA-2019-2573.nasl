#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132290);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2016-10255",
    "CVE-2017-7607",
    "CVE-2017-7608",
    "CVE-2017-7610",
    "CVE-2017-7611",
    "CVE-2017-7612",
    "CVE-2017-7613",
    "CVE-2019-7148",
    "CVE-2019-7150",
    "CVE-2019-7665"
  );

  script_name(english:"EulerOS 2.0 SP3 : elfutils (EulerOS-SA-2019-2573)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the elfutils packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The __libelf_set_rawdata_wrlock function in
    elf_getdata.c in elfutils before 0.168 allows remote
    attackers to cause a denial of service (crash) via a
    crafted (1) sh_off or (2) sh_size ELF header value,
    which triggers a memory allocation
    failure.(CVE-2016-10255)

  - The check_group function in elflint.c in elfutils 0.168
    allows remote attackers to cause a denial of service
    (heap-based buffer over-read and application crash) via
    a crafted ELF file.(CVE-2017-7610)

  - The check_symtab_shndx function in elflint.c in
    elfutils 0.168 allows remote attackers to cause a
    denial of service (heap-based buffer over-read and
    application crash) via a crafted ELF
    file.(CVE-2017-7611)

  - The check_sysv_hash function in elflint.c in elfutils
    0.168 allows remote attackers to cause a denial of
    service (heap-based buffer over-read and application
    crash) via a crafted ELF file.(CVE-2017-7612)

  - The ebl_object_note_type_name function in
    eblobjnotetypename.c in elfutils 0.168 allows remote
    attackers to cause a denial of service (heap-based
    buffer over-read and application crash) via a crafted
    ELF file.(CVE-2017-7608)

  - The handle_gnu_hash function in readelf.c in elfutils
    0.168 allows remote attackers to cause a denial of
    service (heap-based buffer over-read and application
    crash) via a crafted ELF file.(CVE-2017-7607)

  - elflint.c in elfutils 0.168 does not validate the
    number of sections and the number of segments, which
    allows remote attackers to cause a denial of service
    (memory consumption) via a crafted ELF
    file.(CVE-2017-7613)

  - **DISPUTED** An attempted excessive memory allocation
    was discovered in the function read_long_names in
    elf_begin.c in libelf in elfutils 0.174. Remote
    attackers could leverage this vulnerability to cause a
    denial-of-service via crafted elf input, which leads to
    an out-of-memory exception. NOTE: The maintainers
    believe this is not a real issue, but instead a
    'warning caused by ASAN because the allocation is big.
    By setting ASAN_OPTIONS=allocator_may_return_null=1 and
    running the reproducer, nothing
    happens.'(CVE-2019-7148)

  - An issue was discovered in elfutils 0.175. A
    segmentation fault can occur in the function
    elf64_xlatetom in libelf/elf32_xlatetom.c, due to
    dwfl_segment_report_module not checking whether the dyn
    data read from a core file is truncated. A crafted
    input can cause a program crash, leading to
    denial-of-service, as demonstrated by
    eu-stack.(CVE-2019-7150)

  - In elfutils 0.175, a heap-based buffer over-read was
    discovered in the function elf32_xlatetom in
    elf32_xlatetom.c in libelf. A crafted ELF input can
    cause a segmentation fault leading to denial of service
    (program crash) because ebl_core_note does not reject
    malformed core file notes.(CVE-2019-7665)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2573
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c29815ef");
  script_set_attribute(attribute:"solution", value:
"Update the affected elfutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7665");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-7148");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:elfutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:elfutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:elfutils-libelf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:elfutils-libelf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:elfutils-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["elfutils-0.163-3.h6",
        "elfutils-devel-0.163-3.h6",
        "elfutils-libelf-0.163-3.h6",
        "elfutils-libelf-devel-0.163-3.h6",
        "elfutils-libs-0.163-3.h6"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "elfutils");
}
