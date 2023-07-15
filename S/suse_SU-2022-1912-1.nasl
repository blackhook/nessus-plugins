##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1912-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(161827);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2018-11206",
    "CVE-2018-14032",
    "CVE-2018-14033",
    "CVE-2018-14460",
    "CVE-2018-17234",
    "CVE-2018-17237",
    "CVE-2018-17432",
    "CVE-2018-17433",
    "CVE-2018-17434",
    "CVE-2018-17436",
    "CVE-2018-17437",
    "CVE-2018-17438",
    "CVE-2020-10809",
    "CVE-2020-10810",
    "CVE-2020-10811"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1912-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : hdf5 (SUSE-SU-2022:1912-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:1912-1 advisory.

  - An out of bounds read was discovered in H5O_fill_new_decode and H5O_fill_old_decode in H5Ofill.c in the
    HDF HDF5 1.10.2 library. It could allow a remote denial of service or information disclosure attack.
    (CVE-2018-11206)

  - An issue was discovered in the HDF HDF5 1.8.20 library. There is a heap-based buffer over-read in the
    function H5O_layout_decode in H5Olayout.c, related to HDmemcpy. (CVE-2018-14033)

  - An issue was discovered in the HDF HDF5 1.8.20 library. There is a heap-based buffer over-read in the
    function H5O_sdspace_decode in H5Osdspace.c. (CVE-2018-14460)

  - Memory leak in the H5O__chunk_deserialize() function in H5Ocache.c in the HDF HDF5 through 1.10.3 library
    allows attackers to cause a denial of service (memory consumption) via a crafted HDF5 file.
    (CVE-2018-17234)

  - A SIGFPE signal is raised in the function H5D__chunk_set_info_real() of H5Dchunk.c in the HDF HDF5 1.10.3
    library during an attempted parse of a crafted HDF file, because of incorrect protection against division
    by zero. This issue is different from CVE-2018-11207. (CVE-2018-17237)

  - A NULL pointer dereference in H5O_sdspace_encode() in H5Osdspace.c in the HDF HDF5 through 1.10.3 library
    allows attackers to cause a denial of service via a crafted HDF5 file. (CVE-2018-17432)

  - A heap-based buffer overflow in ReadGifImageDesc() in gifread.c in the HDF HDF5 through 1.10.3 library
    allows attackers to cause a denial of service via a crafted HDF5 file. This issue was triggered while
    converting a GIF file to an HDF file. (CVE-2018-17433)

  - A SIGFPE signal is raised in the function apply_filters() of h5repack_filters.c in the HDF HDF5 through
    1.10.3 library during an attempted parse of a crafted HDF file, because of incorrect protection against
    division by zero. It could allow a remote denial of service attack. (CVE-2018-17434)

  - ReadCode() in decompress.c in the HDF HDF5 through 1.10.3 library allows attackers to cause a denial of
    service (invalid write access) via a crafted HDF5 file. This issue was triggered while converting a GIF
    file to an HDF file. (CVE-2018-17436)

  - Memory leak in the H5O_dtype_decode_helper() function in H5Odtype.c in the HDF HDF5 through 1.10.3 library
    allows attackers to cause a denial of service (memory consumption) via a crafted HDF5 file.
    (CVE-2018-17437)

  - A SIGFPE signal is raised in the function H5D__select_io() of H5Dselect.c in the HDF HDF5 through 1.10.3
    library during an attempted parse of a crafted HDF file, because of incorrect protection against division
    by zero. It could allow a remote denial of service attack. (CVE-2018-17438)

  - An issue was discovered in HDF5 through 1.12.0. A heap-based buffer overflow exists in the function
    Decompress() located in decompress.c. It can be triggered by sending a crafted file to the gif2h5 binary.
    It allows an attacker to cause Denial of Service. (CVE-2020-10809)

  - An issue was discovered in HDF5 through 1.12.0. A NULL pointer dereference exists in the function
    H5AC_unpin_entry() located in H5AC.c. It allows an attacker to cause Denial of Service. (CVE-2020-10810)

  - An issue was discovered in HDF5 through 1.12.0. A heap-based buffer over-read exists in the function
    H5O__layout_decode() located in H5Olayout.c. It allows an attacker to cause Denial of Service.
    (CVE-2020-10811)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1093657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1101471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1101474");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1102175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1109167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1109168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1109564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1109565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1109566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1109568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1109569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1109570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167401");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196682");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-June/011219.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3a50ab1");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-11206");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14032");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14033");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14460");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-17234");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-17237");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-17432");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-17433");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-17434");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-17436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-17437");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-17438");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10811");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14460");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-mpich-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-mvapich2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-openmpi3-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-openmpi4-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-hpc-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-hpc-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-mpich-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-mpich-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-mpich-hpc-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-mvapich2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-mvapich2-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-mvapich2-hpc-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-openmpi3-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-openmpi3-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-openmpi3-hpc-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-openmpi4-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-openmpi4-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-openmpi4-hpc-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-hpc-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_1_10_8-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_1_10_8-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_1_10_8-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_1_10_8-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_1_10_8-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp_1_10_8-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp_1_10_8-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp_1_10_8-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp_1_10_8-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp_1_10_8-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran_1_10_8-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran_1_10_8-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran_1_10_8-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran_1_10_8-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran_1_10_8-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_1_10_8-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_1_10_8-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_1_10_8-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_1_10_8-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_1_10_8-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp_1_10_8-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp_1_10_8-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp_1_10_8-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp_1_10_8-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp_1_10_8-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_fortran-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_fortran-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_fortran-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_fortran-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_fortran-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5hl_fortran_1_10_8-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5hl_fortran_1_10_8-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5hl_fortran_1_10_8-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5hl_fortran_1_10_8-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5hl_fortran_1_10_8-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.3|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'hdf5-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-hpc-devel-1.10.8-150300.4.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-hpc-devel-1.10.8-150300.4.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-mpich-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-mpich-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-mvapich2-hpc-devel-1.10.8-150300.4.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-mvapich2-hpc-devel-1.10.8-150300.4.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-openmpi3-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-openmpi3-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-openmpi4-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-gnu-openmpi4-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-hpc-examples-1.10.8-150300.4.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5-hpc-examples-1.10.8-150300.4.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-devel-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-devel-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-devel-static-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-devel-static-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-module-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-module-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-devel-static-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-devel-static-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-module-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-module-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-devel-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-devel-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-devel-static-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-devel-static-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-module-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-module-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-devel-static-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-devel-static-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-module-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-module-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-devel-static-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-devel-static-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-module-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-module-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-hpc-examples-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-hpc-examples-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-devel-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-devel-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-devel-static-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-devel-static-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-module-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-module-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-devel-static-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-devel-static-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-module-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-module-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-devel-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-devel-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-devel-static-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-devel-static-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-module-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-module-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-devel-static-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-devel-static-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-module-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-module-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-devel-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-devel-static-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-devel-static-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-module-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-module-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-hpc-examples-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5_1_10_8-hpc-examples-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-hpc-release-15.3']},
    {'reference':'hdf5-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5-gnu-hpc-devel-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5-gnu-mpich-hpc-devel-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5-gnu-mvapich2-hpc-devel-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5-gnu-openmpi3-hpc-devel-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5-gnu-openmpi4-hpc-devel-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5-hpc-examples-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-devel-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-devel-static-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-hpc-module-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-devel-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-devel-static-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-module-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-devel-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-devel-static-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-module-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-devel-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-devel-static-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-module-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-devel-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-devel-static-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-module-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5_1_10_8-hpc-examples-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'hdf5-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5-gnu-hpc-devel-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5-gnu-mpich-hpc-devel-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5-gnu-mvapich2-hpc-devel-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5-gnu-openmpi3-hpc-devel-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5-gnu-openmpi4-hpc-devel-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5-hpc-examples-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-hpc-devel-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-hpc-devel-static-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-hpc-module-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-devel-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-devel-static-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-module-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-devel-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-devel-static-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-module-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-devel-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-devel-static-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-module-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-devel-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-devel-static-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-module-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'hdf5_1_10_8-hpc-examples-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-mpich-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-mvapich2-hpc-1.10.8-150300.4.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-openmpi3-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-openmpi4-hpc-1.10.8-150300.4.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hdf5-gnu-hpc / hdf5-gnu-hpc-devel / hdf5-gnu-mpich-hpc / etc');
}
