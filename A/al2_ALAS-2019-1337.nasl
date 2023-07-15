#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1337.
#

include("compat.inc");

if (description)
{
  script_id(130233);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/18");

  script_cve_id("CVE-2018-16062", "CVE-2018-16402", "CVE-2018-16403", "CVE-2018-18310", "CVE-2018-18520", "CVE-2018-18521", "CVE-2019-7149", "CVE-2019-7150", "CVE-2019-7664", "CVE-2019-7665");
  script_xref(name:"ALAS", value:"2019-1337");

  script_name(english:"Amazon Linux 2 : elfutils (ALAS-2019-1337)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An out-of-bounds read was discovered in elfutils in the way it reads
DWARF address ranges information. Function dwarf_getaranges() in
dwarf_getaranges.c does not properly check whether it reads beyond the
limits of the ELF section. An attacker could use this flaw to cause a
denial of service via a crafted file.(CVE-2018-16062)

libelf/elf_end.c in elfutils 0.173 allows remote attackers to cause a
denial of service (double free and application crash) or possibly have
unspecified other impact because it tries to decompress
twice.(CVE-2018-16402)

libdw in elfutils 0.173 checks the end of the attributes list
incorrectly in dwarf_getabbrev in dwarf_getabbrev.c and dwarf_hasattr
in dwarf_hasattr.c, leading to a heap-based buffer over-read and an
application crash.(CVE-2018-16403)

An invalid memory address dereference was discovered in
dwfl_segment_report_module.c in libdwfl in elfutils through v0.174.
The vulnerability allows attackers to cause a denial of service
(application crash) with a crafted ELF file, as demonstrated by
consider_notes.(CVE-2018-18310)

An Invalid Memory Address Dereference exists in the function elf_end
in libelf in elfutils through v0.174. Although eu-size is intended to
support ar files inside ar files, handle_ar in size.c closes the outer
ar file before handling all inner entries. The vulnerability allows
attackers to cause a denial of service (application crash) with a
crafted ELF file.(CVE-2018-18520)

Divide-by-zero vulnerabilities in the function arlib_add_symbols() in
arlib.c in elfutils 0.174 allow remote attackers to cause a denial of
service (application crash) with a crafted ELF file, as demonstrated
by eu-ranlib, because a zero sh_entsize is mishandled.(CVE-2018-18521)

A heap-based buffer over-read was discovered in the function
read_srclines in dwarf_getsrclines.c in libdw in elfutils 0.175. A
crafted input can cause segmentation faults, leading to
denial-of-service, as demonstrated by eu-nm.(CVE-2019-7149)

An issue was discovered in elfutils 0.175. A segmentation fault can
occur in the function elf64_xlatetom in libelf/elf32_xlatetom.c, due
to dwfl_segment_report_module not checking whether the dyn data read
from a core file is truncated. A crafted input can cause a program
crash, leading to denial-of-service, as demonstrated by
eu-stack.(CVE-2019-7150)

In elfutils 0.175, a negative-sized memcpy is attempted in
elf_cvt_note in libelf/note_xlate.h because of an incorrect overflow
check. Crafted elf input causes a segmentation fault, leading to
denial of service (program crash).(CVE-2019-7664)

In elfutils 0.175, a heap-based buffer over-read was discovered in the
function elf32_xlatetom in elf32_xlatetom.c in libelf. A crafted ELF
input can cause a segmentation fault leading to denial of service
(program crash) because ebl_core_note does not reject malformed core
file notes.(CVE-2019-7665)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1337.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update elfutils' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils-default-yama-scope");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils-libelf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils-libelf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils-libelf-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");
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
if (rpm_check(release:"AL2", reference:"elfutils-0.176-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"elfutils-debuginfo-0.176-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"elfutils-default-yama-scope-0.176-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"elfutils-devel-0.176-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"elfutils-devel-static-0.176-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"elfutils-libelf-0.176-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"elfutils-libelf-devel-0.176-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"elfutils-libelf-devel-static-0.176-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"elfutils-libs-0.176-2.amzn2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "elfutils / elfutils-debuginfo / elfutils-default-yama-scope / etc");
}
