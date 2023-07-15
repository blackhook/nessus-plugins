#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1277-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(170226);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2017-13735",
    "CVE-2017-14608",
    "CVE-2018-5801",
    "CVE-2018-5805",
    "CVE-2018-5806",
    "CVE-2018-19565",
    "CVE-2018-19566",
    "CVE-2018-19567",
    "CVE-2018-19568",
    "CVE-2018-19655",
    "CVE-2021-3624"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1277-1");

  script_name(english:"openSUSE 15 Security Update : dcraw (SUSE-SU-2022:1277-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
SUSE-SU-2022:1277-1 advisory.

  - There is a floating point exception in the kodak_radc_load_raw function in dcraw_common.cpp in LibRaw
    0.18.2. It will lead to a remote denial of service attack. (CVE-2017-13735)

  - In LibRaw through 0.18.4, an out of bounds read flaw related to kodak_65000_load_raw has been reported in
    dcraw/dcraw.c and internal/dcraw_common.cpp. An attacker could possibly exploit this flaw to disclose
    potentially sensitive memory or cause an application crash. (CVE-2017-14608)

  - A buffer over-read in crop_masked_pixels in dcraw through 9.28 could be used by attackers able to supply
    malicious files to crash an application that bundles the dcraw code or leak private information.
    (CVE-2018-19565)

  - A heap buffer over-read in parse_tiff_ifd in dcraw through 9.28 could be used by attackers able to supply
    malicious files to crash an application that bundles the dcraw code or leak private information.
    (CVE-2018-19566)

  - A floating point exception in parse_tiff_ifd in dcraw through 9.28 could be used by attackers able to
    supply malicious files to crash an application that bundles the dcraw code. (CVE-2018-19567)

  - A floating point exception in kodak_radc_load_raw in dcraw through 9.28 could be used by attackers able to
    supply malicious files to crash an application that bundles the dcraw code. (CVE-2018-19568)

  - A stack-based buffer overflow in the find_green() function of dcraw through 9.28, as used in ufraw-batch
    and many other products, may allow a remote attacker to cause a control-flow hijack, denial-of-service, or
    unspecified other impact via a maliciously crafted raw photo file. (CVE-2018-19655)

  - An error within the LibRaw::unpack() function (src/libraw_cxx.cpp) in LibRaw versions prior to 0.18.7
    can be exploited to trigger a NULL pointer dereference. (CVE-2018-5801)

  - A boundary error within the quicktake_100_load_raw() function (internal/dcraw_common.cpp) in LibRaw
    versions prior to 0.18.8 can be exploited to cause a stack-based buffer overflow and subsequently cause a
    crash. (CVE-2018-5805)

  - An error within the leaf_hdr_load_raw() function (internal/dcraw_common.cpp) in LibRaw versions prior to
    0.18.8 can be exploited to trigger a NULL pointer dereference. (CVE-2018-5806)

  - There is an integer overflow vulnerability in dcraw. When the victim runs dcraw with a maliciously crafted
    X3F input image, arbitrary code may be executed in the victim's system. (CVE-2021-3624)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1056170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1063798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1084690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1097973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1097974");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1117436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1117512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1117517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1117622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1117896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189642");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-April/010775.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e627c6b4");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-14608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19565");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19568");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19655");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-5801");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-5805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-5806");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3624");
  script_set_attribute(attribute:"solution", value:
"Update the affected dcraw and / or dcraw-lang packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3624");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-14608");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^SUSE") audit(AUDIT_OS_NOT, "openSUSE");
var os_ver = pregmatch(pattern: "^(SUSE[\d.]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SUSE15\.3)$", string:os_ver)) audit(AUDIT_OS_NOT, 'openSUSE 15', 'openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE (' + os_ver + ')', cpu);

var pkgs = [
    {'reference':'dcraw-9.28.0-150000.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'dcraw-lang-9.28.0-150000.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dcraw / dcraw-lang');
}
