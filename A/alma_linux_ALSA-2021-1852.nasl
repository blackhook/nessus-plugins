#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2021:1852.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157475);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id(
    "CVE-2020-14373",
    "CVE-2020-16287",
    "CVE-2020-16288",
    "CVE-2020-16289",
    "CVE-2020-16290",
    "CVE-2020-16291",
    "CVE-2020-16292",
    "CVE-2020-16293",
    "CVE-2020-16294",
    "CVE-2020-16295",
    "CVE-2020-16296",
    "CVE-2020-16297",
    "CVE-2020-16298",
    "CVE-2020-16299",
    "CVE-2020-16300",
    "CVE-2020-16301",
    "CVE-2020-16302",
    "CVE-2020-16303",
    "CVE-2020-16304",
    "CVE-2020-16305",
    "CVE-2020-16306",
    "CVE-2020-16307",
    "CVE-2020-16308",
    "CVE-2020-16309",
    "CVE-2020-16310",
    "CVE-2020-17538"
  );
  script_xref(name:"ALSA", value:"2021:1852");
  script_xref(name:"IAVB", value:"2020-B-0046-S");

  script_name(english:"AlmaLinux 8 : ghostscript (ALSA-2021:1852)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2021:1852 advisory.

  - A use after free was found in igc_reloc_struct_ptr() of psi/igc.c of ghostscript-9.25. A local attacker
    could supply a specially crafted PDF file to cause a denial of service. (CVE-2020-14373)

  - A buffer overflow vulnerability in lprn_is_black() in contrib/lips4/gdevlprn.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16287)

  - A buffer overflow vulnerability in pj_common_print_page() in devices/gdevpjet.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16288)

  - A buffer overflow vulnerability in cif_print_page() in devices/gdevcif.c of Artifex Software GhostScript
    v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is fixed in
    v9.51. (CVE-2020-16289)

  - A buffer overflow vulnerability in jetp3852_print_page() in devices/gdev3852.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16290)

  - A buffer overflow vulnerability in contrib/gdevdj9.c of Artifex Software GhostScript v9.50 allows a remote
    attacker to cause a denial of service via a crafted PDF file. This is fixed in v9.51. (CVE-2020-16291)

  - A buffer overflow vulnerability in mj_raster_cmd() in contrib/japanese/gdevmjc.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16292)

  - A null pointer dereference vulnerability in compose_group_nonknockout_nonblend_isolated_allmask_common()
    in base/gxblend.c of Artifex Software GhostScript v9.50 allows a remote attacker to cause a denial of
    service via a crafted PDF file. This is fixed in v9.51. (CVE-2020-16293)

  - A buffer overflow vulnerability in epsc_print_page() in devices/gdevepsc.c of Artifex Software GhostScript
    v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is fixed in
    v9.51. (CVE-2020-16294)

  - A null pointer dereference vulnerability in clj_media_size() in devices/gdevclj.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16295)

  - A buffer overflow vulnerability in GetNumWrongData() in contrib/lips4/gdevlips.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16296)

  - A buffer overflow vulnerability in FloydSteinbergDitheringC() in contrib/gdevbjca.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16297)

  - A buffer overflow vulnerability in mj_color_correct() in contrib/japanese/gdevmjc.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16298)

  - A Division by Zero vulnerability in bj10v_print_page() in contrib/japanese/gdev10v.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16299)

  - A buffer overflow vulnerability in tiff12_print_page() in devices/gdevtfnx.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16300)

  - A buffer overflow vulnerability in okiibm_print_page1() in devices/gdevokii.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16301)

  - A buffer overflow vulnerability in jetp3852_print_page() in devices/gdev3852.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to escalate privileges via a crafted PDF file. This is fixed in
    v9.51. (CVE-2020-16302)

  - A use-after-free vulnerability in xps_finish_image_path() in devices/vector/gdevxps.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to escalate privileges via a crafted PDF file. This is fixed in
    v9.51. (CVE-2020-16303)

  - A buffer overflow vulnerability in image_render_color_thresh() in base/gxicolor.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to escalate privileges via a crafted eps file. This is fixed in
    v9.51. (CVE-2020-16304)

  - A buffer overflow vulnerability in pcx_write_rle() in contrib/japanese/gdev10v.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16305)

  - A null pointer dereference vulnerability in devices/gdevtsep.c of Artifex Software GhostScript v9.50
    allows a remote attacker to cause a denial of service via a crafted postscript file. This is fixed in
    v9.51. (CVE-2020-16306)

  - A null pointer dereference vulnerability in devices/vector/gdevtxtw.c and psi/zbfont.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted postscript file.
    This is fixed in v9.51. (CVE-2020-16307)

  - A buffer overflow vulnerability in p_print_image() in devices/gdevcdj.c of Artifex Software GhostScript
    v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is fixed in
    v9.51. (CVE-2020-16308)

  - A buffer overflow vulnerability in lxm5700m_print_page() in devices/gdevlxm.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted eps file. This is
    fixed in v9.51. (CVE-2020-16309)

  - A division by zero vulnerability in dot24_print_page() in devices/gdevdm24.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16310)

  - A buffer overflow vulnerability in GetNumSameData() in contrib/lips4/gdevlips.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-17538)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2021-1852.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16303");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ghostscript-tools-dvipdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ghostscript-tools-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ghostscript-tools-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ghostscript-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libgs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libgs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'ghostscript-9.27-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ghostscript-doc-9.27-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ghostscript-tools-dvipdf-9.27-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ghostscript-tools-fonts-9.27-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ghostscript-tools-printing-9.27-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ghostscript-x11-9.27-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgs-9.27-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgs-9.27-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgs-devel-9.27-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgs-devel-9.27-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ghostscript / ghostscript-doc / ghostscript-tools-dvipdf / etc');
}
