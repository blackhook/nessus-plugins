#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3207-2.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(118303);
  script_version("1.4");
  script_cvs_date("Date: 2019/09/10 13:51:49");

  script_cve_id("CVE-2014-9939", "CVE-2017-15938", "CVE-2017-15939", "CVE-2017-15996", "CVE-2017-16826", "CVE-2017-16827", "CVE-2017-16828", "CVE-2017-16829", "CVE-2017-16830", "CVE-2017-16831", "CVE-2017-16832", "CVE-2017-6965", "CVE-2017-6966", "CVE-2017-6969", "CVE-2017-7209", "CVE-2017-7210", "CVE-2017-7223", "CVE-2017-7224", "CVE-2017-7225", "CVE-2017-7226", "CVE-2017-7299", "CVE-2017-7300", "CVE-2017-7301", "CVE-2017-7302", "CVE-2017-7303", "CVE-2017-7304", "CVE-2017-8392", "CVE-2017-8393", "CVE-2017-8394", "CVE-2017-8396", "CVE-2017-8421", "CVE-2017-9746", "CVE-2017-9747", "CVE-2017-9748", "CVE-2017-9750", "CVE-2017-9755", "CVE-2017-9756", "CVE-2018-10372", "CVE-2018-10373", "CVE-2018-10534", "CVE-2018-10535", "CVE-2018-6323", "CVE-2018-6543", "CVE-2018-6759", "CVE-2018-6872", "CVE-2018-7208", "CVE-2018-7568", "CVE-2018-7569", "CVE-2018-7570", "CVE-2018-7642", "CVE-2018-7643", "CVE-2018-8945");

  script_name(english:"SUSE SLES12 Security Update : binutils (SUSE-SU-2018:3207-2)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for binutils to 2.31 fixes the following issues :

These security issues were fixed :

CVE-2017-15996: readelf allowed remote attackers to cause a denial of
service (excessive memory allocation) or possibly have unspecified
other impact via a crafted ELF file that triggered a buffer overflow
on fuzzed archive header (bsc#1065643).

CVE-2017-15939: Binary File Descriptor (BFD) library (aka libbfd)
mishandled NULL files in a .debug_line file table, which allowed
remote attackers to cause a denial of service (NULL pointer
dereference and application crash) via a crafted ELF file, related to
concat_filename (bsc#1065689).

CVE-2017-15938: the Binary File Descriptor (BFD) library (aka libbfd)
miscalculated DW_FORM_ref_addr die refs in the case of a relocatable
object file, which allowed remote attackers to cause a denial of
service (find_abstract_instance_name invalid memory read, segmentation
fault, and application crash) (bsc#1065693).

CVE-2017-16826: The coff_slurp_line_table function the Binary File
Descriptor (BFD) library (aka libbfd) allowed remote attackers to
cause a denial of service (invalid memory access and application
crash) or possibly have unspecified other impact via a crafted PE file
(bsc#1068640).

CVE-2017-16832: The pe_bfd_read_buildid function in the Binary File
Descriptor (BFD) library (aka libbfd) did not validate size and offset
values in the data dictionary, which allowed remote attackers to cause
a denial of service (segmentation violation and application crash) or
possibly have unspecified other impact via a crafted PE file
(bsc#1068643).

CVE-2017-16831: Binary File Descriptor (BFD) library (aka libbfd) did
not validate the symbol count, which allowed remote attackers to cause
a denial of service (integer overflow and application crash, or
excessive memory allocation) or possibly have unspecified other impact
via a crafted PE file (bsc#1068887).

CVE-2017-16830: The print_gnu_property_note function did not have
integer-overflow protection on 32-bit platforms, which allowed remote
attackers to cause a denial of service (segmentation violation and
application crash) or possibly have unspecified other impact via a
crafted ELF file (bsc#1068888).

CVE-2017-16829: The _bfd_elf_parse_gnu_properties function in the
Binary File Descriptor (BFD) library (aka libbfd) did not prevent
negative pointers, which allowed remote attackers to cause a denial of
service (out-of-bounds read and application crash) or possibly have
unspecified other impact via a crafted ELF file (bsc#1068950).

CVE-2017-16828: The display_debug_frames function allowed remote
attackers to cause a denial of service (integer overflow and
heap-based buffer over-read, and application crash) or possibly have
unspecified other impact via a crafted ELF file (bsc#1069176).

CVE-2017-16827: The aout_get_external_symbols function in the Binary
File Descriptor (BFD) library (aka libbfd) allowed remote attackers to
cause a denial of service (slurp_symtab invalid free and application
crash) or possibly have unspecified other impact via a crafted ELF
file (bsc#1069202).

CVE-2018-6323: The elf_object_p function in the Binary File Descriptor
(BFD) library (aka libbfd) had an unsigned integer overflow because
bfd_size_type multiplication is not used. A crafted ELF file allowed
remote attackers to cause a denial of service (application crash) or
possibly have unspecified other impact (bsc#1077745).

CVE-2018-6543: Prevent integer overflow in the function
load_specific_debug_section() which resulted in `malloc()` with 0
size. A crafted ELF file allowed remote attackers to cause a denial of
service (application crash) or possibly have unspecified other impact
(bsc#1079103).

CVE-2018-6759: The bfd_get_debug_link_info_1 function in the Binary
File Descriptor (BFD) library (aka libbfd) had an unchecked strnlen
operation. Remote attackers could have leveraged this vulnerability to
cause a denial of service (segmentation fault) via a crafted ELF file
(bsc#1079741).

CVE-2018-6872: The elf_parse_notes function in the Binary File
Descriptor (BFD) library (aka libbfd) allowed remote attackers to
cause a denial of service (out-of-bounds read and segmentation
violation) via a note with a large alignment (bsc#1080556).

CVE-2018-7208: In the coff_pointerize_aux function in the Binary File
Descriptor (BFD) library (aka libbfd) an index was not validated,
which allowed remote attackers to cause a denial of service
(segmentation fault) or possibly have unspecified other impact via a
crafted file, as demonstrated by objcopy of a COFF object
(bsc#1081527).

CVE-2018-7570: The assign_file_positions_for_non_load_sections
function in the Binary File Descriptor (BFD) library (aka libbfd)
allowed remote attackers to cause a denial of service (NULL pointer
dereference and application crash) via an ELF file with a RELRO
segment that lacks a matching LOAD segment, as demonstrated by objcopy
(bsc#1083528).

CVE-2018-7569: The Binary File Descriptor (BFD) library (aka libbfd)
allowed remote attackers to cause a denial of service (integer
underflow or overflow, and application crash) via an ELF file with a
corrupt DWARF FORM block, as demonstrated by nm (bsc#1083532).

CVE-2018-8945: The bfd_section_from_shdr function in the Binary File
Descriptor (BFD) library (aka libbfd) allowed remote attackers to
cause a denial of service (segmentation fault) via a large attribute
section (bsc#1086608).

CVE-2018-7643: The display_debug_ranges function allowed remote
attackers to cause a denial of service (integer overflow and
application crash) or possibly have unspecified other impact via a
crafted ELF file, as demonstrated by objdump (bsc#1086784).

CVE-2018-7642: The swap_std_reloc_in function in the Binary File
Descriptor (BFD) library (aka libbfd) allowed remote attackers to
cause a denial of service (aout_32_swap_std_reloc_out NULL pointer
dereference and application crash) via a crafted ELF file, as
demonstrated by objcopy (bsc#1086786).

CVE-2018-7568: The parse_die function in the Binary File Descriptor
(BFD) library (aka libbfd) allowed remote attackers to cause a denial
of service (integer overflow and application crash) via an ELF file
with corrupt dwarf1 debug information, as demonstrated by nm
(bsc#1086788).

CVE-2018-10373: concat_filename in the Binary File Descriptor (BFD)
library (aka libbfd) allowed remote attackers to cause a denial of
service (NULL pointer dereference and application crash) via a crafted
binary file, as demonstrated by nm-new (bsc#1090997).

CVE-2018-10372: process_cu_tu_index allowed remote attackers to cause
a denial of service (heap-based buffer over-read and application
crash) via a crafted binary file, as demonstrated by readelf
(bsc#1091015).

CVE-2018-10535: The ignore_section_sym function in the Binary File
Descriptor (BFD) library (aka libbfd) did not validate the
output_section pointer in the case of a symtab entry with a 'SECTION'
type that has a '0' value, which allowed remote attackers to cause a
denial of service (NULL pointer dereference and application crash) via
a crafted file, as demonstrated by objcopy (bsc#1091365).

CVE-2018-10534: The _bfd_XX_bfd_copy_private_bfd_data_common function
in the Binary File Descriptor (BFD) library (aka libbfd) processesed a
negative Data Directory size with an unbounded loop that increased the
value of (external_IMAGE_DEBUG_DIRECTORY) *edd so that the address
exceeded its own memory region, resulting in an out-of-bounds memory
write, as demonstrated by objcopy copying private info with
_bfd_pex64_bfd_copy_private_bfd_data_common in pex64igen.c
(bsc#1091368).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1030296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1030297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1030298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1030584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1030585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1030588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1030589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1031590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1031593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1031595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1031638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1031644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1031656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1044891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1044897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1044901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1044909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1044925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1044927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1065643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1065689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1065693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1069176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1069202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1077745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1079103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1079741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1080556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1081527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1085784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9939/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15938/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15939/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15996/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16826/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16827/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16828/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16829/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16830/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16831/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16832/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6965/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6966/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6969/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7209/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7210/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7223/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7224/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7225/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7226/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7299/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7300/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7301/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7302/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7303/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7304/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8392/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8393/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8394/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8396/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8421/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9746/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9747/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9748/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9750/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9755/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9756/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10372/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10373/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10534/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10535/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6323/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6543/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6759/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6872/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7208/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7568/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7569/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7570/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7642/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7643/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-8945/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183207-2/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3cc9a535"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2018-2297=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"binutils-2.31-9.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"binutils-debuginfo-2.31-9.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"binutils-debugsource-2.31-9.26.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils");
}
