#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1185.
#

include("compat.inc");

if (description)
{
  script_id(123469);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/27");

  script_cve_id("CVE-2017-12448", "CVE-2017-12449", "CVE-2017-12450", "CVE-2017-12451", "CVE-2017-12452", "CVE-2017-12453", "CVE-2017-12454", "CVE-2017-12455", "CVE-2017-12456", "CVE-2017-12457", "CVE-2017-12458", "CVE-2017-12459", "CVE-2017-13710");
  script_xref(name:"ALAS", value:"2019-1185");

  script_name(english:"Amazon Linux 2 : binutils (ALAS-2019-1185)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The _bfd_xcoff_read_ar_hdr function in bfd/coff-rs6000.c and
bfd/coff64-rs6000.c in the Binary File Descriptor (BFD) library (aka
libbfd), as distributed in GNU Binutils 2.29 and earlier, allows
remote attackers to cause an out of bounds stack read via a crafted
COFF image file.(CVE-2017-12451)

The evax_bfd_print_emh function in vms-alpha.c in the Binary File
Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils
2.29 and earlier, allows remote attackers to cause an out of bounds
heap read via a crafted vms alpha file.(CVE-2017-12455)

The setup_group function in elf.c in the Binary File Descriptor (BFD)
library (aka libbfd), as distributed in GNU Binutils 2.29, allows
remote attackers to cause a denial of service (NULL pointer
dereference and application crash) via a group section that is too
small.(CVE-2017-13710)

The nlm_swap_auxiliary_headers_in function in bfd/nlmcode.h in the
Binary File Descriptor (BFD) library (aka libbfd), as distributed in
GNU Binutils 2.29 and earlier, allows remote attackers to cause an out
of bounds heap read via a crafted nlm file.(CVE-2017-12458)

The _bfd_vms_slurp_egsd function in bfd/vms-alpha.c in the Binary File
Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils
2.29 and earlier, allows remote attackers to cause an arbitrary memory
read via a crafted vms alpha file.(CVE-2017-12454)

The _bfd_vms_slurp_eeom function in libbfd.c in the Binary File
Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils
2.29 and earlier, allows remote attackers to cause an out of bounds
heap read via a crafted vms alpha file.(CVE-2017-12453)

The alpha_vms_object_p function in bfd/vms-alpha.c in the Binary File
Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils
2.29 and earlier, allows remote attackers to cause an out of bounds
heap write and possibly achieve code execution via a crafted vms alpha
file.(CVE-2017-12450)

The read_symbol_stabs_debugging_info function in rddbg.c in GNU
Binutils 2.29 and earlier allows remote attackers to cause an out of
bounds heap read via a crafted binary file.(CVE-2017-12456)

The bfd_mach_o_read_symtab_strtab function in bfd/mach-o.c in the
Binary File Descriptor (BFD) library (aka libbfd), as distributed in
GNU Binutils 2.29 and earlier, allows remote attackers to cause an out
of bounds heap write and possibly achieve code execution via a crafted
mach-o file.(CVE-2017-12459)

The _bfd_vms_save_sized_string function in vms-misc.c in the Binary
File Descriptor (BFD) library (aka libbfd), as distributed in GNU
Binutils 2.29 and earlier, allows remote attackers to cause an out of
bounds heap read via a crafted vms file.(CVE-2017-12449)

The bfd_make_section_with_flags function in section.c in the Binary
File Descriptor (BFD) library (aka libbfd), as distributed in GNU
Binutils 2.29 and earlier, allows remote attackers to cause a NULL
dereference via a crafted file.(CVE-2017-12457)

The bfd_mach_o_i386_canonicalize_one_reloc function in
bfd/mach-o-i386.c in the Binary File Descriptor (BFD) library (aka
libbfd), as distributed in GNU Binutils 2.29 and earlier, allows
remote attackers to cause an out of bounds heap read via a crafted
mach-o file.(CVE-2017-12452)

The bfd_cache_close function in bfd/cache.c in the Binary File
Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils
2.29 and earlier, allows remote attackers to cause a heap use after
free and possibly achieve code execution via a crafted nested archive
file. This issue occurs because incorrect functions are called during
an attempt to release memory. The issue can be addressed by better
input validation in the bfd_generic_archive_p function in
bfd/archive.c.(CVE-2017-12448)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1185.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update binutils' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
