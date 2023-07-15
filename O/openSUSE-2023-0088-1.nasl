#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0088-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(174145);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id(
    "CVE-2021-20285",
    "CVE-2021-30500",
    "CVE-2021-30501",
    "CVE-2021-43311",
    "CVE-2021-43312",
    "CVE-2021-43313",
    "CVE-2021-43314",
    "CVE-2021-43315",
    "CVE-2021-43316",
    "CVE-2021-43317",
    "CVE-2023-23456",
    "CVE-2023-23457"
  );

  script_name(english:"openSUSE 15 Security Update : upx (openSUSE-SU-2023:0088-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2023:0088-1 advisory.

  - A flaw was found in upx canPack in p_lx_elf.cpp in UPX 3.96. This flaw allows attackers to cause a denial
    of service (SEGV or buffer overflow and application crash) or possibly have unspecified other impacts via
    a crafted ELF. The highest threat from this vulnerability is to system availability. (CVE-2021-20285)

  - Null pointer dereference was found in upx PackLinuxElf::canUnpack() in p_lx_elf.cpp,in version UPX 4.0.0.
    That allow attackers to execute arbitrary code and cause a denial of service via a crafted file.
    (CVE-2021-30500)

  - An assertion abort was found in upx MemBuffer::alloc() in mem.cpp, in version UPX 4.0.0. The flow allows
    attackers to cause a denial of service (abort) via a crafted file. (CVE-2021-30501)

  - A heap-based buffer overflow was discovered in upx, during the generic pointer 'p' points to an
    inaccessible address in func get_le32(). The problem is essentially caused in PackLinuxElf32::elf_lookup()
    at p_lx_elf.cpp:5382. (CVE-2021-43311)

  - A heap-based buffer overflow was discovered in upx, during the variable 'bucket' points to an inaccessible
    address. The issue is being triggered in the function PackLinuxElf64::invert_pt_dynamic at
    p_lx_elf.cpp:5239. (CVE-2021-43312)

  - A heap-based buffer overflow was discovered in upx, during the variable 'bucket' points to an inaccessible
    address. The issue is being triggered in the function PackLinuxElf32::invert_pt_dynamic at
    p_lx_elf.cpp:1688. (CVE-2021-43313)

  - A heap-based buffer overflows was discovered in upx, during the generic pointer 'p' points to an
    inaccessible address in func get_le32(). The problem is essentially caused in PackLinuxElf32::elf_lookup()
    at p_lx_elf.cpp:5368 (CVE-2021-43314)

  - A heap-based buffer overflows was discovered in upx, during the generic pointer 'p' points to an
    inaccessible address in func get_le32(). The problem is essentially caused in PackLinuxElf32::elf_lookup()
    at p_lx_elf.cpp:5349 (CVE-2021-43315)

  - A heap-based buffer overflow was discovered in upx, during the generic pointer 'p' points to an
    inaccessible address in func get_le64(). (CVE-2021-43316)

  - A heap-based buffer overflows was discovered in upx, during the generic pointer 'p' points to an
    inaccessible address in func get_le32(). The problem is essentially caused in PackLinuxElf64::elf_lookup()
    at p_lx_elf.cpp:5404 (CVE-2021-43317)

  - A heap-based buffer overflow issue was discovered in UPX in PackTmt::pack() in p_tmt.cpp file. The flow
    allows an attacker to cause a denial of service (abort) via a crafted file. (CVE-2023-23456)

  - A Segmentation fault was found in UPX in PackLinuxElf64::invert_pt_dynamic() in p_lx_elf.cpp. An attacker
    with a crafted input file allows invalid memory address access that could lead to a denial of service.
    (CVE-2023-23457)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207121");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207122");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209771");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XLSYENIWX7YMHJJKVRBH2CPDXM5X3IW6/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?599e7773");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30500");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30501");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43311");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43312");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43313");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43314");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43315");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43316");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43317");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23456");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23457");
  script_set_attribute(attribute:"solution", value:
"Update the affected upx package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20285");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-30500");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:upx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.4)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.4', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'upx-4.0.2-bp154.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'upx');
}
