#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0096. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154500);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id(
    "CVE-2017-12448",
    "CVE-2018-12934",
    "CVE-2018-17794",
    "CVE-2018-18483",
    "CVE-2018-18605",
    "CVE-2018-19931",
    "CVE-2019-14444"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : binutils Multiple Vulnerabilities (NS-SA-2021-0096)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has binutils packages installed that are affected
by multiple vulnerabilities:

  - The bfd_cache_close function in bfd/cache.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause a heap use after free and
    possibly achieve code execution via a crafted nested archive file. This issue occurs because incorrect
    functions are called during an attempt to release memory. The issue can be addressed by better input
    validation in the bfd_generic_archive_p function in bfd/archive.c. (CVE-2017-12448)

  - remember_Ktype in cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.30, allows attackers to
    trigger excessive memory consumption (aka OOM). This can occur during execution of cxxfilt.
    (CVE-2018-12934)

  - An issue was discovered in cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.31. There is a
    NULL pointer dereference in work_stuff_copy_to_from when called from iterate_demangle_function.
    (CVE-2018-17794)

  - The get_count function in cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.31, allows remote
    attackers to cause a denial of service (malloc called with the result of an integer-overflowing
    calculation) or possibly have unspecified other impact via a crafted string, as demonstrated by c++filt.
    (CVE-2018-18483)

  - A heap-based buffer over-read issue was discovered in the function sec_merge_hash_lookup in merge.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.31, because
    _bfd_add_merge_section mishandles section merges when size is not a multiple of entsize. A specially
    crafted ELF allows remote attackers to cause a denial of service, as demonstrated by ld. (CVE-2018-18605)

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils through 2.31. There is a heap-based buffer overflow in bfd_elf32_swap_phdr_in in elfcode.h
    because the number of program headers is not restricted. (CVE-2018-19931)

  - apply_relocations in readelf.c in GNU Binutils 2.32 contains an integer overflow that allows attackers to
    trigger a write access violation (in byte_put_little_endian function in elfcomm.c) via an ELF file, as
    demonstrated by readelf. (CVE-2019-14444)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0096");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2017-12448");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-12934");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-17794");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-18483");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-18605");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-19931");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-14444");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL binutils packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19931");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'binutils-2.27-41.base.el7.cgslv5_4.0.2.g67a582a',
    'binutils-debuginfo-2.27-41.base.el7.cgslv5_4.0.2.g67a582a',
    'binutils-devel-2.27-41.base.el7.cgslv5_4.0.2.g67a582a'
  ],
  'CGSL MAIN 5.04': [
    'binutils-2.27-41.base.el7.cgslv5_4.0.2.g67a582a',
    'binutils-debuginfo-2.27-41.base.el7.cgslv5_4.0.2.g67a582a',
    'binutils-devel-2.27-41.base.el7.cgslv5_4.0.2.g67a582a'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'binutils');
}
