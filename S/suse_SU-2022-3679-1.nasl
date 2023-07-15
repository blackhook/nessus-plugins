#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3679-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(166371);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id(
    "CVE-2022-0561",
    "CVE-2022-2519",
    "CVE-2022-2520",
    "CVE-2022-2521",
    "CVE-2022-2867",
    "CVE-2022-2868",
    "CVE-2022-2869",
    "CVE-2022-34266",
    "CVE-2022-34526"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3679-1");

  script_name(english:"SUSE SLES12 Security Update : tiff (SUSE-SU-2022:3679-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:3679-1 advisory.

  - Null source pointer passed as an argument to memcpy() function within TIFFFetchStripThing() in
    tif_dirread.c in libtiff versions from 3.9.0 to 4.3.0 could lead to Denial of Service via crafted TIFF
    file. For users that compile libtiff from sources, the fix is available with commit eecb0712.
    (CVE-2022-0561)

  - There is a double free or corruption in rotateImage() at tiffcrop.c:8839 found in libtiff 4.4.0rc1
    (CVE-2022-2519)

  - A flaw was found in libtiff 4.4.0rc1. There is a sysmalloc assertion fail in rotateImage() at
    tiffcrop.c:8621 that can cause program crash when reading a crafted input. (CVE-2022-2520)

  - It was found in libtiff 4.4.0rc1 that there is an invalid pointer free operation in TIFFClose() at
    tif_close.c:131 called by tiffcrop.c:2522 that can cause a program crash and denial of service while
    processing crafted input. (CVE-2022-2521)

  - libtiff's tiffcrop utility has a uint32_t underflow that can lead to out of bounds read and write. An
    attacker who supplies a crafted file to tiffcrop (likely via tricking a user to run tiffcrop on it with
    certain parameters) could cause a crash or in some cases, further exploitation. (CVE-2022-2867)

  - libtiff's tiffcrop utility has a improper input validation flaw that can lead to out of bounds read and
    ultimately cause a crash if an attacker is able to supply a crafted file to tiffcrop. (CVE-2022-2868)

  - libtiff's tiffcrop tool has a uint32_t underflow which leads to out of bounds read and write in the
    extractContigSamples8bits routine. An attacker who supplies a crafted file to tiffcrop could trigger this
    flaw, most likely by tricking a user into opening the crafted file with tiffcrop. Triggering this flaw
    could cause a crash or potentially further exploitation. (CVE-2022-2869)

  - The libtiff-4.0.3-35.amzn2.0.1 package for LibTIFF on Amazon Linux 2 allows attackers to cause a denial of
    service (application crash), a different vulnerability than CVE-2022-0562. When processing a malicious
    TIFF file, an invalid range may be passed as an argument to the memset() function within
    TIFFFetchStripThing() in tif_dirread.c. This will cause TIFFFetchStripThing() to segfault after use of an
    uninitialized resource. (CVE-2022-34266)

  - A stack overflow was discovered in the _TIFFVGetField function of Tiffsplit v4.4.0. This vulnerability
    allows attackers to cause a Denial of Service (DoS) via a crafted TIFF file parsed by the tiffsplit or
    tiffcrop utilities. (CVE-2022-34526)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202973");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-October/012592.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ed05446");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0561");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2519");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2520");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2521");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2869");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34266");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34526");
  script_set_attribute(attribute:"solution", value:
"Update the affected libtiff-devel, libtiff5, libtiff5-32bit and / or tiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0561");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-34526");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libtiff5-32bit-4.0.9-44.56.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libtiff5-4.0.9-44.56.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'tiff-4.0.9-44.56.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libtiff-devel-4.0.9-44.56.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libtiff5-32bit-4.0.9-44.56.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libtiff5-4.0.9-44.56.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'tiff-4.0.9-44.56.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libtiff5-32bit-4.0.9-44.56.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'libtiff5-4.0.9-44.56.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'tiff-4.0.9-44.56.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'libtiff5-32bit-4.0.9-44.56.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.3']},
    {'reference':'libtiff5-4.0.9-44.56.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.3']},
    {'reference':'tiff-4.0.9-44.56.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.3']},
    {'reference':'libtiff5-32bit-4.0.9-44.56.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libtiff5-4.0.9-44.56.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'tiff-4.0.9-44.56.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtiff-devel / libtiff5 / libtiff5-32bit / tiff');
}
