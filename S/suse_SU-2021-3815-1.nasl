#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3815-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155748);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/01");

  script_cve_id(
    "CVE-2019-20005",
    "CVE-2019-20006",
    "CVE-2019-20007",
    "CVE-2019-20198",
    "CVE-2019-20199",
    "CVE-2019-20200",
    "CVE-2019-20201",
    "CVE-2019-20202",
    "CVE-2021-26220",
    "CVE-2021-26221",
    "CVE-2021-26222",
    "CVE-2021-30485",
    "CVE-2021-31229",
    "CVE-2021-31347",
    "CVE-2021-31348",
    "CVE-2021-31598"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3815-1");

  script_name(english:"SUSE SLES15 Security Update : netcdf (SUSE-SU-2021:3815-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:3815-1 advisory.

  - An issue was discovered in ezXML 0.8.3 through 0.8.6. The function ezxml_decode, while parsing a crafted
    XML file, performs incorrect memory handling, leading to a heap-based buffer over-read while running
    strchr() starting with a pointer after a '\0' character (where the processing of a string was finished).
    (CVE-2019-20005)

  - An issue was discovered in ezXML 0.8.3 through 0.8.6. The function ezxml_char_content puts a pointer to
    the internal address of a larger block as xml->txt. This is later deallocated (using free), leading to a
    segmentation fault. (CVE-2019-20006)

  - An issue was discovered in ezXML 0.8.2 through 0.8.6. The function ezxml_str2utf8, while parsing a crafted
    XML file, performs zero-length reallocation in ezxml.c, leading to returning a NULL pointer (in some
    compilers). After this, the function ezxml_parse_str does not check whether the s variable is not NULL in
    ezxml.c, leading to a NULL pointer dereference and crash (segmentation fault). (CVE-2019-20007)

  - An issue was discovered in ezXML 0.8.3 through 0.8.6. The function ezxml_ent_ok() mishandles recursion,
    leading to stack consumption for a crafted XML file. (CVE-2019-20198)

  - An issue was discovered in ezXML 0.8.3 through 0.8.6. The function ezxml_decode, while parsing a crafted
    XML file, performs incorrect memory handling, leading to NULL pointer dereference while running strlen()
    on a NULL pointer. (CVE-2019-20199)

  - An issue was discovered in ezXML 0.8.3 through 0.8.6. The function ezxml_decode, while parsing crafted a
    XML file, performs incorrect memory handling, leading to a heap-based buffer over-read in the normalize
    line endings feature. (CVE-2019-20200)

  - An issue was discovered in ezXML 0.8.3 through 0.8.6. The ezxml_parse_* functions mishandle XML entities,
    leading to an infinite loop in which memory allocations occur. (CVE-2019-20201)

  - An issue was discovered in ezXML 0.8.3 through 0.8.6. The function ezxml_char_content() tries to use
    realloc on a block that was not allocated, leading to an invalid free and segmentation fault.
    (CVE-2019-20202)

  - The ezxml_toxml function in ezxml 0.8.6 and earlier is vulnerable to OOB write when opening XML file after
    exhausting the memory pool. (CVE-2021-26220)

  - The ezxml_new function in ezXML 0.8.6 and earlier is vulnerable to OOB write when opening XML file after
    exhausting the memory pool. (CVE-2021-26221, CVE-2021-26222)

  - An issue was discovered in libezxml.a in ezXML 0.8.6. The function ezxml_internal_dtd(), while parsing a
    crafted XML file, performs incorrect memory handling, leading to a NULL pointer dereference while running
    strcmp() on a NULL pointer. (CVE-2021-30485)

  - An issue was discovered in libezxml.a in ezXML 0.8.6. The function ezxml_internal_dtd() performs incorrect
    memory handling while parsing crafted XML files, which leads to an out-of-bounds write of a one byte
    constant. (CVE-2021-31229)

  - An issue was discovered in libezxml.a in ezXML 0.8.6. The function ezxml_parse_str() performs incorrect
    memory handling while parsing crafted XML files (writing outside a memory region created by mmap).
    (CVE-2021-31347)

  - An issue was discovered in libezxml.a in ezXML 0.8.6. The function ezxml_parse_str() performs incorrect
    memory handling while parsing crafted XML files (out-of-bounds read after a certain strcspn failure).
    (CVE-2021-31348)

  - An issue was discovered in libezxml.a in ezXML 0.8.6. The function ezxml_decode() performs incorrect
    memory handling while parsing crafted XML files, leading to a heap-based buffer overflow. (CVE-2021-31598)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191856");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-November/009780.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3daec3e4");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20005");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20198");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20199");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20200");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20202");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-26220");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-26221");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-26222");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30485");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-31229");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-31347");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-31348");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-31598");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26222");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf-gnu-openmpi2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf_4_6_1-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf_4_6_1-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf_4_6_1-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf_4_6_1-gnu-openmpi2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-mpich-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-mvapich2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-openmpi2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-openmpi2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_6_1-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_6_1-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_6_1-gnu-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_6_1-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_6_1-gnu-mpich-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_6_1-gnu-mpich-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_6_1-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_6_1-gnu-mvapich2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_6_1-gnu-mvapich2-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_6_1-gnu-openmpi2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_6_1-gnu-openmpi2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_6_1-gnu-openmpi2-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'libnetcdf-gnu-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'libnetcdf-gnu-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'libnetcdf-gnu-mpich-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'libnetcdf-gnu-mpich-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'libnetcdf-gnu-mvapich2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'libnetcdf-gnu-mvapich2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'libnetcdf-gnu-openmpi2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'libnetcdf-gnu-openmpi2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'libnetcdf_4_6_1-gnu-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'libnetcdf_4_6_1-gnu-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'libnetcdf_4_6_1-gnu-mpich-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'libnetcdf_4_6_1-gnu-mpich-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'libnetcdf_4_6_1-gnu-mvapich2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'libnetcdf_4_6_1-gnu-mvapich2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'libnetcdf_4_6_1-gnu-openmpi2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'libnetcdf_4_6_1-gnu-openmpi2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf-gnu-hpc-4.6.1-10.7.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf-gnu-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf-gnu-mpich-hpc-4.6.1-10.7.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf-gnu-mpich-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf-gnu-mvapich2-hpc-4.6.1-10.7.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf-gnu-mvapich2-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf-gnu-openmpi2-hpc-4.6.1-10.7.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf-gnu-openmpi2-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-hpc-devel-static-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-hpc-devel-static-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-mpich-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-mpich-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-mpich-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-mpich-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-mpich-hpc-devel-static-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-mpich-hpc-devel-static-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-mvapich2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-mvapich2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-mvapich2-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-mvapich2-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-mvapich2-hpc-devel-static-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-mvapich2-hpc-devel-static-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-openmpi2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-openmpi2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-openmpi2-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-openmpi2-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-openmpi2-hpc-devel-static-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'netcdf_4_6_1-gnu-openmpi2-hpc-devel-static-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'libnetcdf-gnu-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'libnetcdf-gnu-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'libnetcdf-gnu-mpich-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'libnetcdf-gnu-mpich-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'libnetcdf-gnu-mvapich2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'libnetcdf-gnu-mvapich2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'libnetcdf-gnu-openmpi2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'libnetcdf-gnu-openmpi2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'libnetcdf_4_6_1-gnu-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'libnetcdf_4_6_1-gnu-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'libnetcdf_4_6_1-gnu-mpich-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'libnetcdf_4_6_1-gnu-mpich-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'libnetcdf_4_6_1-gnu-mvapich2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'libnetcdf_4_6_1-gnu-mvapich2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'libnetcdf_4_6_1-gnu-openmpi2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'libnetcdf_4_6_1-gnu-openmpi2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf-gnu-hpc-4.6.1-10.7.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf-gnu-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf-gnu-mpich-hpc-4.6.1-10.7.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf-gnu-mpich-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf-gnu-mvapich2-hpc-4.6.1-10.7.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf-gnu-mvapich2-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf-gnu-openmpi2-hpc-4.6.1-10.7.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf-gnu-openmpi2-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-hpc-devel-static-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-hpc-devel-static-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-mpich-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-mpich-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-mpich-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-mpich-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-mpich-hpc-devel-static-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-mpich-hpc-devel-static-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-mvapich2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-mvapich2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-mvapich2-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-mvapich2-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-mvapich2-hpc-devel-static-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-mvapich2-hpc-devel-static-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-openmpi2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-openmpi2-hpc-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-openmpi2-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-openmpi2-hpc-devel-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-openmpi2-hpc-devel-static-4.6.1-10.7.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'netcdf_4_6_1-gnu-openmpi2-hpc-devel-static-4.6.1-10.7.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnetcdf-gnu-hpc / libnetcdf-gnu-mpich-hpc / etc');
}
