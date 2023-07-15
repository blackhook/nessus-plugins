#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-af305bed3d
#

include('compat.inc');

if (description)
{
  script_id(173663);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id(
    "CVE-2022-34612",
    "CVE-2022-36040",
    "CVE-2022-36041",
    "CVE-2022-36042",
    "CVE-2022-36043",
    "CVE-2022-36044"
  );
  script_xref(name:"FEDORA", value:"2023-af305bed3d");

  script_name(english:"Fedora 38 : cutter-re / rizin (2023-af305bed3d)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2023-af305bed3d advisory.

  - Rizin v0.4.0 and below was discovered to contain an integer overflow via the function get_long_object().
    This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted binary.
    (CVE-2022-34612)

  - Rizin is a UNIX-like reverse engineering framework and command-line toolset. Versions 0.4.0 and prior are
    vulnerable to an out-of-bounds write when getting data from dyld cache files. A user opening a malicious
    dyld cache file could be affected by this vulnerability, allowing an attacker to execute code on the
    user's machine. Commit number 556ca2f9eef01ec0f4a76d1fbacfcf3a87a44810 contains a patch. (CVE-2022-36042)

  - Rizin is a UNIX-like reverse engineering framework and command-line toolset. Versions 0.4.0 and prior are
    vulnerable to an out-of-bounds write when getting data from PYC(python) files. A user opening a malicious
    PYC file could be affected by this vulnerability, allowing an attacker to execute code on the user's
    machine. Commit number 68948017423a12786704e54227b8b2f918c2fd27 contains a patch. (CVE-2022-36040)

  - Rizin is a UNIX-like reverse engineering framework and command-line toolset. Versions 0.4.0 and prior are
    vulnerable to an out-of-bounds write when parsing Mach-O files. A user opening a malicious Mach-O file
    could be affected by this vulnerability, allowing an attacker to execute code on the user's machine.
    Commit number 7323e64d68ecccfb0ed3ee480f704384c38676b2 contains a patch. (CVE-2022-36041)

  - Rizin is a UNIX-like reverse engineering framework and command-line toolset. Versions 0.4.0 and prior are
    vulnerable to a double free in bobj.c:rz_bin_reloc_storage_free() when freeing relocations generated from
    qnx binary plugin. A user opening a malicious qnx binary could be affected by this vulnerability, allowing
    an attacker to execute code on the user's machine. Commit number a3d50c1ea185f3f642f2d8180715f82d98840784
    contains a patch for this issue. (CVE-2022-36043)

  - Rizin is a UNIX-like reverse engineering framework and command-line toolset. Versions 0.4.0 and prior are
    vulnerable to an out-of-bounds write when getting data from Luac files. A user opening a malicious Luac
    file could be affected by this vulnerability, allowing an attacker to execute code on the user's machine.
    Commits 07b43bc8aa1ffebd9b68d60624c9610cf7e460c7 and 05bbd147caccc60162d6fba9baaaf24befa281cd contain
    fixes for the issue. (CVE-2022-36044)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-af305bed3d");
  script_set_attribute(attribute:"solution", value:
"Update the affected cutter-re and / or rizin packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-36044");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cutter-re");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rizin");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'cutter-re-2.2.0-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rizin-0.5.1-1.fc38.2', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cutter-re / rizin');
}
