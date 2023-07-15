#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1129-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159599);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2016-1924",
    "CVE-2016-3183",
    "CVE-2016-4797",
    "CVE-2018-14423",
    "CVE-2018-16375",
    "CVE-2018-16376",
    "CVE-2018-20845",
    "CVE-2018-20846",
    "CVE-2020-8112",
    "CVE-2020-15389",
    "CVE-2020-27823",
    "CVE-2021-29338",
    "CVE-2022-1122"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1129-1");

  script_name(english:"SUSE SLES12 Security Update : openjpeg2 (SUSE-SU-2022:1129-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:1129-1 advisory.

  - The opj_tgt_reset function in OpenJpeg 2016.1.18 allows remote attackers to cause a denial of service
    (out-of-bounds read and application crash) via a crafted JPEG 2000 image. (CVE-2016-1924)

  - The sycc422_t_rgb function in common/color.c in OpenJPEG before 2.1.1 allows remote attackers to cause a
    denial of service (out-of-bounds read) via a crafted jpeg2000 file. (CVE-2016-3183)

  - Divide-by-zero vulnerability in the opj_tcd_init_tile function in tcd.c in OpenJPEG before 2.1.1 allows
    remote attackers to cause a denial of service (application crash) via a crafted jp2 file. NOTE: this issue
    exists because of an incorrect fix for CVE-2014-7947. (CVE-2016-4797)

  - Division-by-zero vulnerabilities in the functions pi_next_pcrl, pi_next_cprl, and pi_next_rpcl in
    lib/openjp3d/pi.c in OpenJPEG through 2.3.0 allow remote attackers to cause a denial of service
    (application crash). (CVE-2018-14423)

  - An issue was discovered in OpenJPEG 2.3.0. Missing checks for header_info.height and header_info.width in
    the function pnmtoimage in bin/jpwl/convert.c can lead to a heap-based buffer overflow. (CVE-2018-16375)

  - An issue was discovered in OpenJPEG 2.3.0. A heap-based buffer overflow was discovered in the function
    t2_encode_packet in lib/openmj2/t2.c. The vulnerability causes an out-of-bounds write, which may lead to
    remote denial of service or possibly unspecified other impact. (CVE-2018-16376)

  - Division-by-zero vulnerabilities in the functions pi_next_pcrl, pi_next_cprl, and pi_next_rpcl in
    openmj2/pi.c in OpenJPEG through 2.3.0 allow remote attackers to cause a denial of service (application
    crash). (CVE-2018-20845)

  - Out-of-bounds accesses in the functions pi_next_lrcp, pi_next_rlcp, pi_next_rpcl, pi_next_pcrl,
    pi_next_rpcl, and pi_next_cprl in openmj2/pi.c in OpenJPEG through 2.3.0 allow remote attackers to cause a
    denial of service (application crash). (CVE-2018-20846)

  - jp2/opj_decompress.c in OpenJPEG through 2.3.1 has a use-after-free that can be triggered if there is a
    mix of valid and invalid files in a directory operated on by the decompressor. Triggering a double-free
    may also be possible. This is related to calling opj_image_destroy twice. (CVE-2020-15389)

  - A flaw was found in OpenJPEG's encoder. This flaw allows an attacker to pass specially crafted x,y offset
    input to OpenJPEG to use during encoding. The highest threat from this vulnerability is to
    confidentiality, integrity, as well as system availability. (CVE-2020-27823)

  - opj_t1_clbl_decode_processor in openjp2/t1.c in OpenJPEG 2.3.1 through 2020-01-28 has a heap-based buffer
    overflow in the qmfbid==1 case, a different issue than CVE-2020-6851. (CVE-2020-8112)

  - Integer Overflow in OpenJPEG v2.4.0 allows remote attackers to crash the application, causing a Denial of
    Service (DoS). This occurs when the attacker uses the command line option -ImgDir on a directory that
    contains 1048576 files. (CVE-2021-29338)

  - A flaw was found in the opj2_decompress program in openjpeg2 2.4.0 in the way it handles an input
    directory with a large number of files. When it fails to allocate a buffer to store the filenames of the
    input directory, it calls free() on an uninitialized pointer, leading to a segmentation fault and a denial
    of service. (CVE-2022-1122)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/971617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/980504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1102016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1106881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1106882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1140130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1140205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1162090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197738");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-April/010666.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d923ebf9");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-1924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-3183");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-4797");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14423");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16375");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16376");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15389");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8112");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29338");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1122");
  script_set_attribute(attribute:"solution", value:
"Update the affected libopenjp2-7 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8112");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenjp2-7");
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
    {'reference':'libopenjp2-7-2.1.0-4.15.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libopenjp2-7-2.1.0-4.15.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libopenjp2-7-2.1.0-4.15.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libopenjp2-7-2.1.0-4.15.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'libopenjp2-7-2.1.0-4.15.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libopenjp2-7-2.1.0-4.15.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenjp2-7');
}
