#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1138.
#

include("compat.inc");

if (description)
{
  script_id(121047);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2018-10372", "CVE-2018-10373", "CVE-2018-10535", "CVE-2018-13033", "CVE-2018-6323", "CVE-2018-7208", "CVE-2018-7568", "CVE-2018-7569", "CVE-2018-7643");
  script_xref(name:"ALAS", value:"2019-1138");

  script_name(english:"Amazon Linux 2 : binutils (ALAS-2019-1138)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer wraparound has been discovered in the Binary File
Descriptor (BFD) library distributed in GNU Binutils up to version
2.30. An attacker could cause a crash by providing an ELF file with
corrupted DWARF debug information.(CVE-2018-7568)

The ignore_section_sym function in elf.c in the Binary File Descriptor
(BFD) library (aka libbfd), as distributed in GNU Binutils 2.30, does
not validate the output_section pointer in the case of a symtab entry
with a 'SECTION' type that has a '0' value, which allows remote
attackers to cause a denial of service (NULL pointer dereference and
application crash) via a crafted file, as demonstrated by
objcopy.(CVE-2018-10535)

The display_debug_ranges function in dwarf.c in GNU Binutils 2.30
allows remote attackers to cause a denial of service (integer overflow
and application crash) or possibly have unspecified other impact via a
crafted ELF file, as demonstrated by objdump.(CVE-2018-7643)

concat_filename in dwarf2.c in the Binary File Descriptor (BFD)
library (aka libbfd), as distributed in GNU Binutils 2.30, allows
remote attackers to cause a denial of service (NULL pointer
dereference and application crash) via a crafted binary file, as
demonstrated by nm-new.(CVE-2018-10373)

The elf_object_p function in elfcode.h in the Binary File Descriptor
(BFD) library (aka libbfd), as distributed in GNU Binutils 2.29.1, has
an unsigned integer overflow because bfd_size_type multiplication is
not used. A crafted ELF file allows remote attackers to cause a denial
of service (application crash) or possibly have unspecified other
impact.(CVE-2018-6323)

An integer wraparound has been discovered in the Binary File
Descriptor (BFD) library distributed in GNU Binutils up to version
2.30. An attacker could cause a crash by providing an ELF file with
corrupted DWARF debug information.(CVE-2018-7569)

The Binary File Descriptor (BFD) library (aka libbfd), as distributed
in GNU Binutils 2.30, allows remote attackers to cause a denial of
service (excessive memory allocation and application crash) via a
crafted ELF file, as demonstrated by _bfd_elf_parse_attributes in
elf-attrs.c and bfd_malloc in libbfd.c. This can occur during
execution of nm.(CVE-2018-13033)

process_cu_tu_index in dwarf.c in GNU Binutils 2.30 allows remote
attackers to cause a denial of service (heap-based buffer over-read
and application crash) via a crafted binary file, as demonstrated by
readelf.(CVE-2018-10372)

In the coff_pointerize_aux function in coffgen.c in the Binary File
Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils
2.30, an index is not validated, which allows remote attackers to
cause a denial of service (segmentation fault) or possibly have
unspecified other impact via a crafted file, as demonstrated by
objcopy of a COFF object.(CVE-2018-7208)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1138.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update binutils' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"binutils-2.29.1-27.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"binutils-debuginfo-2.29.1-27.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"binutils-devel-2.29.1-27.amzn2.0.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / binutils-debuginfo / binutils-devel");
}
