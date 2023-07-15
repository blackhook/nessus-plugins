#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:3170-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104968);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-9939", "CVE-2017-12448", "CVE-2017-12450", "CVE-2017-12452", "CVE-2017-12453", "CVE-2017-12454", "CVE-2017-12456", "CVE-2017-12799", "CVE-2017-13757", "CVE-2017-14128", "CVE-2017-14129", "CVE-2017-14130", "CVE-2017-14333", "CVE-2017-14529", "CVE-2017-14729", "CVE-2017-14745", "CVE-2017-14974", "CVE-2017-6965", "CVE-2017-6966", "CVE-2017-6969", "CVE-2017-7209", "CVE-2017-7210", "CVE-2017-7223", "CVE-2017-7224", "CVE-2017-7225", "CVE-2017-7226", "CVE-2017-7227", "CVE-2017-7299", "CVE-2017-7300", "CVE-2017-7301", "CVE-2017-7302", "CVE-2017-7303", "CVE-2017-7304", "CVE-2017-7614", "CVE-2017-8392", "CVE-2017-8393", "CVE-2017-8394", "CVE-2017-8395", "CVE-2017-8396", "CVE-2017-8397", "CVE-2017-8398", "CVE-2017-8421", "CVE-2017-9038", "CVE-2017-9039", "CVE-2017-9040", "CVE-2017-9041", "CVE-2017-9042", "CVE-2017-9043", "CVE-2017-9044", "CVE-2017-9746", "CVE-2017-9747", "CVE-2017-9748", "CVE-2017-9750", "CVE-2017-9755", "CVE-2017-9756", "CVE-2017-9954", "CVE-2017-9955");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : binutils (SUSE-SU-2017:3170-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GNU binutil was updated to the 2.29.1 release, bringing various new
features, fixing a lot of bugs and security issues. Following security
issues are being addressed by this release :

  - 18750 bsc#1030296 CVE-2014-9939

  - 20891 bsc#1030585 CVE-2017-7225

  - 20892 bsc#1030588 CVE-2017-7224

  - 20898 bsc#1030589 CVE-2017-7223

  - 20905 bsc#1030584 CVE-2017-7226

  - 20908 bsc#1031644 CVE-2017-7299

  - 20909 bsc#1031656 CVE-2017-7300

  - 20921 bsc#1031595 CVE-2017-7302

  - 20922 bsc#1031593 CVE-2017-7303

  - 20924 bsc#1031638 CVE-2017-7301

  - 20931 bsc#1031590 CVE-2017-7304

  - 21135 bsc#1030298 CVE-2017-7209

  - 21137 bsc#1029909 CVE-2017-6965

  - 21139 bsc#1029908 CVE-2017-6966

  - 21156 bsc#1029907 CVE-2017-6969

  - 21157 bsc#1030297 CVE-2017-7210

  - 21409 bsc#1037052 CVE-2017-8392

  - 21412 bsc#1037057 CVE-2017-8393

  - 21414 bsc#1037061 CVE-2017-8394

  - 21432 bsc#1037066 CVE-2017-8396

  - 21440 bsc#1037273 CVE-2017-8421

  - 21580 bsc#1044891 CVE-2017-9746

  - 21581 bsc#1044897 CVE-2017-9747

  - 21582 bsc#1044901 CVE-2017-9748

  - 21587 bsc#1044909 CVE-2017-9750

  - 21594 bsc#1044925 CVE-2017-9755

  - 21595 bsc#1044927 CVE-2017-9756

  - 21787 bsc#1052518 CVE-2017-12448

  - 21813 bsc#1052503, CVE-2017-12456, bsc#1052507,
    CVE-2017-12454, bsc#1052509, CVE-2017-12453,
    bsc#1052511, CVE-2017-12452, bsc#1052514,
    CVE-2017-12450, bsc#1052503, CVE-2017-12456,
    bsc#1052507, CVE-2017-12454, bsc#1052509,
    CVE-2017-12453, bsc#1052511, CVE-2017-12452,
    bsc#1052514, CVE-2017-12450

  - 21933 bsc#1053347 CVE-2017-12799

  - 21990 bsc#1058480 CVE-2017-14333

  - 22018 bsc#1056312 CVE-2017-13757

  - 22047 bsc#1057144 CVE-2017-14129

  - 22058 bsc#1057149 CVE-2017-14130

  - 22059 bsc#1057139 CVE-2017-14128

  - 22113 bsc#1059050 CVE-2017-14529

  - 22148 bsc#1060599 CVE-2017-14745

  - 22163 bsc#1061241 CVE-2017-14974

  - 22170 bsc#1060621 CVE-2017-14729 Update to binutils
    2.29. [fate#321454, fate#321494, fate#323293] :

  - The MIPS port now supports microMIPS eXtended Physical
    Addressing (XPA) instructions for assembly and
    disassembly.

  - The MIPS port now supports the microMIPS Release 5 ISA
    for assembly and disassembly.

  - The MIPS port now supports the Imagination interAptiv
    MR2 processor, which implements the MIPS32r3 ISA, the
    MIPS16e2 ASE as well as a couple of
    implementation-specific regular MIPS and MIPS16e2 ASE
    instructions.

  - The SPARC port now supports the SPARC M8 processor,
    which implements the Oracle SPARC Architecture 2017.

  - The MIPS port now supports the MIPS16e2 ASE for assembly
    and disassembly.

  - Add support for ELF SHF_GNU_MBIND and PT_GNU_MBIND_XXX.

  - Add support for the wasm32 ELF conversion of the
    WebAssembly file format.

  - Add --inlines option to objdump, which extends the
    --line-numbers option so that inlined functions will
    display their nesting information.

  - Add --merge-notes options to objcopy to reduce the size
    of notes in a binary file by merging and deleting
    redundant notes.

  - Add support for locating separate debug info files using
    the build-id method, where the separate file has a name
    based upon the build-id of the original file.

  - GAS specific :

  - Add support for ELF SHF_GNU_MBIND.

  - Add support for the WebAssembly file format and wasm32
    ELF conversion.

  - PowerPC gas now checks that the correct register class
    is used in instructions. For instance, 'addi
    %f4,%cr3,%r31' warns three times that the registers are
    invalid.

  - Add support for the Texas Instruments PRU processor.

  - Support for the ARMv8-R architecture and Cortex-R52
    processor has been added to the ARM port.

  - GNU ld specific :

  - Support for -z shstk in the x86 ELF linker to generate
    GNU_PROPERTY_X86_FEATURE_1_SHSTK in ELF GNU program
    properties.

  - Add support for GNU_PROPERTY_X86_FEATURE_1_SHSTK in ELF
    GNU program properties in the x86 ELF linker.

  - Add support for GNU_PROPERTY_X86_FEATURE_1_IBT in ELF
    GNU program properties in the x86 ELF linker.

  - Support for -z ibtplt in the x86 ELF linker to generate
    IBT-enabled PLT.

  - Support for -z ibt in the x86 ELF linker to generate
    IBT-enabled PLT as well as
    GNU_PROPERTY_X86_FEATURE_1_IBT in ELF GNU program
    properties.

  - Add support for ELF SHF_GNU_MBIND and PT_GNU_MBIND_XXX.

  - Add support for ELF GNU program properties.

  - Add support for the Texas Instruments PRU processor.

  - When configuring for arc*-*-linux* targets the default
    linker emulation will change if --with-cpu=nps400 is
    used at configure time.

  - Improve assignment of LMAs to orphan sections in some
    edge cases where a mixture of both AT>LMA_REGION and
    AT(LMA) are used.

  - Orphan sections placed after an empty section that has
    an AT(LMA) will now take an load memory address starting
    from LMA.

  - Section groups can now be resolved (the group deleted
    and the group members placed like normal sections) at
    partial link time either using the new linker option
    --force-group-allocation or by placing
    FORCE_GROUP_ALLOCATION into the linker script.

  - Add riscv64 target, tested with gcc7 and downstream
    newlib 2.4.0

  - Prepare riscv32 target (gh#riscv/riscv-newlib#8)

  - Make compressed debug section handling explicit, disable
    for old products and enable for gas on all architectures
    otherwise. [bsc#1029995]

  - Remove empty rpath component removal optimization from
    to workaround CMake rpath handling. [bsc#1025282] Minor
    security bugs fixed: PR 21147, PR 21148, PR 21149, PR
    21150, PR 21151, PR 21155, PR 21158, PR 21159

  - Update to binutils 2.28.

  - Add support for locating separate debug info files using
    the build-id method, where the separate file has a name
    based upon the build-id of the original file.

  - This version of binutils fixes a problem with PowerPC
    VLE 16A and 16D relocations which were functionally
    swapped, for example, R_PPC_VLE_HA16A performed like
    R_PPC_VLE_HA16D while R_PPC_VLE_HA16D performed like
    R_PPC_VLE_HA16A. This could have been fixed by
    renumbering relocations, which would keep object files
    created by an older version of gas compatible with a
    newer ld. However, that would require an ABI update,
    affecting other assemblers and linkers that create and
    process the relocations correctly. It is recommended
    that all VLE object files be recompiled, but ld can
    modify the relocations if --vle-reloc-fixup is passed to
    ld. If the new ld command line option is not used, ld
    will ld warn on finding relocations inconsistent with
    the instructions being relocated.

  - The nm program has a new command line option
    (--with-version-strings) which will display a symbol's
    version information, if any, after the symbol's name.

  - The ARC port of objdump now accepts a -M option to
    specify the extra instruction class(es) that should be
    disassembled.

  - The --remove-section option for objcopy and strip now
    accepts section patterns starting with an exclamation
    point to indicate a non-matching section. A non-matching
    section is removed from the set of sections matched by
    an earlier --remove-section pattern.

  - The --only-section option for objcopy now accepts
    section patterns starting with an exclamation point to
    indicate a non-matching section. A non-matching section
    is removed from the set of sections matched by an
    earlier --only-section pattern.

  - New --remove-relocations=SECTIONPATTERN option for
    objcopy and strip. This option can be used to remove
    sections containing relocations. The SECTIONPATTERN is
    the section to which the relocations apply, not the
    relocation section itself.

  - GAS specific :

  - Add support for the RISC-V architecture.

  - Add support for the ARM Cortex-M23 and Cortex-M33
    processors.

  - GNU ld specific :

  - The EXCLUDE_FILE linker script construct can now be
    applied outside of the section list in order for the
    exclusions to apply over all input sections in the list.

  - Add support for the RISC-V architecture.

  - The command line option --no-eh-frame-hdr can now be
    used in ELF based linkers to disable the automatic
    generation of .eh_frame_hdr sections.

  - Add --in-implib=<infile> to the ARM linker to enable
    specifying a set of Secure Gateway veneers that must
    exist in the output import library specified by
    --out-implib=<outfile> and the address they must have.
    As such, --in-implib is only supported in combination
    with --cmse-implib.

  - Extended the --out-implib=<file> option, previously
    restricted to x86 PE targets, to any ELF based target.
    This allows the generation of an import library for an
    ELF executable, which can then be used by another
    application to link against the executable.

  - GOLD specific :

  - Add -z bndplt option (x86-64 only) to support Intel MPX.

  - Add --orphan-handling option.

  - Add --stub-group-multi option (PowerPC only).

  - Add --target1-rel, --target1-abs, --target2 options (Arm
    only).

  - Add -z stack-size option.

  - Add --be8 option (Arm only).

  - Add HIDDEN support in linker scripts.

  - Add SORT_BY_INIT_PRIORITY support in linker scripts.

  - Other fixes :

  - Fix section alignment on .gnu_debuglink. [bso#21193]

  - Add s390x to gold_archs.

  - Fix alignment frags for aarch64 (bsc#1003846)

  - Call ldconfig for libbfd

  - Fix an assembler problem with clang on ARM.

  - Restore monotonically increasing section offsets.

  - Update to binutils 2.27.

  - Add a configure option, --enable-64-bit-archive, to
    force use of a 64-bit format when creating an archive
    symbol index.

  - Add --elf-stt-common= option to objcopy for ELF targets
    to control whether to convert common symbols to the
    STT_COMMON type.

  - GAS specific :

  - Default to --enable-compressed-debug-sections=gas for
    Linux/x86 targets.

  - Add --no-pad-sections to stop the assembler from padding
    the end of output sections up to their alignment
    boundary.

  - Support for the ARMv8-M architecture has been added to
    the ARM port. Support for the ARMv8-M Security and DSP
    Extensions has also been added to the ARM port.

  - ARC backend accepts .extInstruction, .extCondCode,
    .extAuxRegister, and .extCoreRegister pseudo-ops that
    allow an user to define custom instructions, conditional
    codes, auxiliary and core registers.

  - Add a configure option --enable-elf-stt-common to decide
    whether ELF assembler should generate common symbols
    with the STT_COMMON type by default. Default to no.

  - New command line option --elf-stt-common= for ELF
    targets to control whether to generate common symbols
    with the STT_COMMON type.

  - Add ability to set section flags and types via numeric
    values for ELF based targets.

  - Add a configure option --enable-x86-relax-relocations to
    decide whether x86 assembler should generate relax
    relocations by default. Default to yes, except for x86
    Solaris targets older than Solaris 12.

  - New command line option -mrelax-relocations= for x86
    target to control whether to generate relax relocations.

  - New command line option -mfence-as-lock-add=yes for x86
    target to encode lfence, mfence and sfence as 'lock addl
    $0x0, (%[re]sp)'.

  - Add assembly-time relaxation option for ARC cpus.

  - Add --with-cpu=TYPE configure option for ARC gas. This
    allows the default cpu type to be adjusted at configure
    time.

  - GOLD specific :

  - Add a configure option --enable-relro to decide whether
    -z relro should be enabled by default. Default to yes.

  - Add support for s390, MIPS, AArch64, and TILE-Gx
    architectures.

  - Add support for STT_GNU_IFUNC symbols.

  - Add support for incremental linking (--incremental).

  - GNU ld specific :

  - Add a configure option --enable-relro to decide whether
    -z relro should be enabled in ELF linker by default.
    Default to yes for all Linux targets except FRV, HPPA,
    IA64 and MIPS.

  - Support for -z noreloc-overflow in the x86-64 ELF linker
    to disable relocation overflow check.

  - Add -z common/-z nocommon options for ELF targets to
    control whether to convert common symbols to the
    STT_COMMON type during a relocatable link.

  - Support for -z nodynamic-undefined-weak in the x86 ELF
    linker, which avoids dynamic relocations against
    undefined weak symbols in executable.

  - The NOCROSSREFSTO command was added to the linker script
    language.

  - Add --no-apply-dynamic-relocs to the AArch64 linker to
    do not apply link-time values for dynamic
    relocations.</file></outfile></infile>

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1003846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1025282"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029995"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1030583"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033122"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1038874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1038875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1038876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1038877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1038878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1038880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1038881"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1046094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1053347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=437293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=445037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=546106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=561142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=578249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=590820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=691290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=698346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=713504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=776968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=863764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=938658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9939/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12448/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12450/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12452/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12453/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12454/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12456/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12799/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13757/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14128/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14129/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14130/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14333/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14529/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14729/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14745/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14974/"
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
    value:"https://www.suse.com/security/cve/CVE-2017-7227/"
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
    value:"https://www.suse.com/security/cve/CVE-2017-7614/"
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
    value:"https://www.suse.com/security/cve/CVE-2017-8395/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8396/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8397/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8398/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8421/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9038/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9039/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9040/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9041/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9042/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9043/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9044/"
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
    value:"https://www.suse.com/security/cve/CVE-2017-9954/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9955/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20173170-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ef1d319"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2017-1971=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-1971=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2017-1971=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1971=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2017-1971=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1971=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-1971=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1971=1

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2017-1971=1

To bring your system up-to-date, use 'zypper patch'."
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
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"binutils-2.29.1-9.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"binutils-debuginfo-2.29.1-9.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"binutils-debugsource-2.29.1-9.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"binutils-2.29.1-9.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"binutils-debuginfo-2.29.1-9.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"binutils-debugsource-2.29.1-9.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"binutils-2.29.1-9.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"binutils-debuginfo-2.29.1-9.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"binutils-debugsource-2.29.1-9.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"binutils-2.29.1-9.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"binutils-debuginfo-2.29.1-9.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"binutils-debugsource-2.29.1-9.20.2")) flag++;


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
