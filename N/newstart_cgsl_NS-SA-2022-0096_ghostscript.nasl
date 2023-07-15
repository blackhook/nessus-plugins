#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0096. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167479);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/15");

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
  script_xref(name:"IAVB", value:"2020-B-0046-S");

  script_name(english:"NewStart CGSL MAIN 6.02 : ghostscript Multiple Vulnerabilities (NS-SA-2022-0096)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has ghostscript packages installed that are affected by
multiple vulnerabilities:

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0096");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14373");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16287");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16288");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16289");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16290");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16291");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16292");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16293");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16294");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16295");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16296");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16297");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16298");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16299");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16300");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16301");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16302");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16303");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16304");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16305");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16306");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16307");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16308");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16309");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16310");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-17538");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL ghostscript packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16303");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libgs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'ghostscript-9.27-1.el8',
    'libgs-9.27-1.el8'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ghostscript');
}
