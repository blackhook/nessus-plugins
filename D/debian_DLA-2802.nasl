#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2802. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154749);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/31");

  script_cve_id(
    "CVE-2018-16062",
    "CVE-2018-16402",
    "CVE-2018-18310",
    "CVE-2018-18520",
    "CVE-2018-18521",
    "CVE-2019-7150",
    "CVE-2019-7665"
  );

  script_name(english:"Debian DLA-2802-1 : elfutils - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2802 advisory.

  - dwarf_getaranges in dwarf_getaranges.c in libdw in elfutils before 2018-08-18 allows remote attackers to
    cause a denial of service (heap-based buffer over-read) via a crafted file. (CVE-2018-16062)

  - libelf/elf_end.c in elfutils 0.173 allows remote attackers to cause a denial of service (double free and
    application crash) or possibly have unspecified other impact because it tries to decompress twice.
    (CVE-2018-16402)

  - An invalid memory address dereference was discovered in dwfl_segment_report_module.c in libdwfl in
    elfutils through v0.174. The vulnerability allows attackers to cause a denial of service (application
    crash) with a crafted ELF file, as demonstrated by consider_notes. (CVE-2018-18310)

  - An Invalid Memory Address Dereference exists in the function elf_end in libelf in elfutils through v0.174.
    Although eu-size is intended to support ar files inside ar files, handle_ar in size.c closes the outer ar
    file before handling all inner entries. The vulnerability allows attackers to cause a denial of service
    (application crash) with a crafted ELF file. (CVE-2018-18520)

  - Divide-by-zero vulnerabilities in the function arlib_add_symbols() in arlib.c in elfutils 0.174 allow
    remote attackers to cause a denial of service (application crash) with a crafted ELF file, as demonstrated
    by eu-ranlib, because a zero sh_entsize is mishandled. (CVE-2018-18521)

  - An issue was discovered in elfutils 0.175. A segmentation fault can occur in the function elf64_xlatetom
    in libelf/elf32_xlatetom.c, due to dwfl_segment_report_module not checking whether the dyn data read from
    a core file is truncated. A crafted input can cause a program crash, leading to denial-of-service, as
    demonstrated by eu-stack. (CVE-2019-7150)

  - In elfutils 0.175, a heap-based buffer over-read was discovered in the function elf32_xlatetom in
    elf32_xlatetom.c in libelf. A crafted ELF input can cause a segmentation fault leading to denial of
    service (program crash) because ebl_core_note does not reject malformed core file notes. (CVE-2019-7665)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=907562");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/elfutils");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2802");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-16062");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-16402");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-18310");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-18520");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-18521");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-7150");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-7665");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/elfutils");
  script_set_attribute(attribute:"solution", value:
"Upgrade the elfutils packages.

For Debian 9 stretch, these problems have been fixed in version 0.168-1+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16402");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:elfutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libasm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libasm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdw-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdw1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libelf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libelf1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'elfutils', 'reference': '0.168-1+deb9u1'},
    {'release': '9.0', 'prefix': 'libasm-dev', 'reference': '0.168-1+deb9u1'},
    {'release': '9.0', 'prefix': 'libasm1', 'reference': '0.168-1+deb9u1'},
    {'release': '9.0', 'prefix': 'libdw-dev', 'reference': '0.168-1+deb9u1'},
    {'release': '9.0', 'prefix': 'libdw1', 'reference': '0.168-1+deb9u1'},
    {'release': '9.0', 'prefix': 'libelf-dev', 'reference': '0.168-1+deb9u1'},
    {'release': '9.0', 'prefix': 'libelf1', 'reference': '0.168-1+deb9u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'elfutils / libasm-dev / libasm1 / libdw-dev / libdw1 / libelf-dev / etc');
}
