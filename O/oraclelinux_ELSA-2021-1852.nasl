#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-1852.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149960);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/26");

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

  script_name(english:"Oracle Linux 8 : ghostscript (ELSA-2021-1852)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-1852 advisory.

  - A use after free was found in igc_reloc_struct_ptr() of psi/igc.c of ghostscript-9.25. A local attacker
    could supply a specially crafted PDF file to cause a denial of service. (CVE-2020-14373)

  - A buffer overflow vulnerability in cif_print_page() in devices/gdevcif.c of Artifex Software GhostScript
    v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is fixed in
    v9.51. (CVE-2020-16289)

  - A buffer overflow vulnerability in jetp3852_print_page() in devices/gdev3852.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16290)

  - A buffer overflow vulnerability in GetNumWrongData() in contrib/lips4/gdevlips.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16296)

  - A buffer overflow vulnerability in FloydSteinbergDitheringC() in contrib/gdevbjca.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16297)

  - A buffer overflow vulnerability in mj_color_correct() in contrib/japanese/gdevmjc.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16298)

  - A buffer overflow vulnerability in image_render_color_thresh() in base/gxicolor.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to escalate privileges via a crafted eps file. This is fixed in
    v9.51. (CVE-2020-16304)

  - A null pointer dereference vulnerability in devices/gdevtsep.c of Artifex Software GhostScript v9.50
    allows a remote attacker to cause a denial of service via a crafted postscript file. This is fixed in
    v9.51. (CVE-2020-16306)

  - A division by zero vulnerability in dot24_print_page() in devices/gdevdm24.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16310)

  - A buffer overflow vulnerability in lprn_is_black() in contrib/lips4/gdevlprn.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16287)

  - A buffer overflow vulnerability in pj_common_print_page() in devices/gdevpjet.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16288)

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

  - A buffer overflow vulnerability in pcx_write_rle() in contrib/japanese/gdev10v.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-16305)

  - A null pointer dereference vulnerability in devices/vector/gdevtxtw.c and psi/zbfont.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted postscript file.
    This is fixed in v9.51. (CVE-2020-16307)

  - A buffer overflow vulnerability in p_print_image() in devices/gdevcdj.c of Artifex Software GhostScript
    v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is fixed in
    v9.51. (CVE-2020-16308)

  - A buffer overflow vulnerability in lxm5700m_print_page() in devices/gdevlxm.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted eps file. This is
    fixed in v9.51. (CVE-2020-16309)

  - A buffer overflow vulnerability in GetNumSameData() in contrib/lips4/gdevlips.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is
    fixed in v9.51. (CVE-2020-17538)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-1852.html");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-tools-dvipdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-tools-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-tools-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgs-devel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'ghostscript-9.27-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ghostscript-9.27-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ghostscript-doc-9.27-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ghostscript-tools-dvipdf-9.27-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ghostscript-tools-dvipdf-9.27-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ghostscript-tools-fonts-9.27-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ghostscript-tools-fonts-9.27-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ghostscript-tools-printing-9.27-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ghostscript-tools-printing-9.27-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ghostscript-x11-9.27-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ghostscript-x11-9.27-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgs-9.27-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgs-9.27-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgs-9.27-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgs-devel-9.27-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgs-devel-9.27-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgs-devel-9.27-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ghostscript / ghostscript-doc / ghostscript-tools-dvipdf / etc');
}
