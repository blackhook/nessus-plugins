#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147424);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/16");

  script_cve_id(
    "CVE-2016-10217",
    "CVE-2016-10218",
    "CVE-2016-10219",
    "CVE-2016-10220",
    "CVE-2016-10317",
    "CVE-2017-11714",
    "CVE-2017-5951",
    "CVE-2017-9612",
    "CVE-2017-9726",
    "CVE-2017-9727",
    "CVE-2017-9739",
    "CVE-2017-9835",
    "CVE-2020-16287",
    "CVE-2020-16288",
    "CVE-2020-16289",
    "CVE-2020-16290",
    "CVE-2020-16291",
    "CVE-2020-16292",
    "CVE-2020-16294",
    "CVE-2020-16295",
    "CVE-2020-16296",
    "CVE-2020-16297",
    "CVE-2020-16298",
    "CVE-2020-16299",
    "CVE-2020-16300",
    "CVE-2020-16301",
    "CVE-2020-16302",
    "CVE-2020-16305",
    "CVE-2020-16308",
    "CVE-2020-16309",
    "CVE-2020-16310",
    "CVE-2020-17538"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.6 : ghostscript (EulerOS-SA-2021-1476)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ghostscript packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A Division by Zero vulnerability in bj10v_print_page()
    in contrib/japanese/gdev10v.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a
    denial of service via a crafted PDF file.
    (CVE-2020-16299)

  - A buffer overflow vulnerability in
    pj_common_print_page() in devices/gdevpjet.c of Artifex
    Software GhostScript v9.50 allows a remote attacker to
    cause a denial of service via a crafted PDF file.
    (CVE-2020-16288)

  - A buffer overflow vulnerability in cif_print_page() in
    devices/gdevcif.c of Artifex Software GhostScript v9.50
    allows a remote attacker to cause a denial of service
    via a crafted PDF file. (CVE-2020-16289)

  - A buffer overflow vulnerability in
    jetp3852_print_page() in devices/gdev3852.c of Artifex
    Software GhostScript v9.50 allows a remote attacker to
    cause a denial of service via a crafted PDF file.
    (CVE-2020-16290)

  - A buffer overflow vulnerability in mj_raster_cmd() in
    contrib/japanese/gdevmjc.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a
    denial of service via a crafted PDF file.
    (CVE-2020-16292)

  - A buffer overflow vulnerability in epsc_print_page() in
    devices/gdevepsc.c of Artifex Software GhostScript
    v9.50 allows a remote attacker to cause a denial of
    service via a crafted PDF file. (CVE-2020-16294)

  - A null pointer dereference vulnerability in
    clj_media_size() in devices/gdevclj.c of Artifex
    Software GhostScript v9.50 allows a remote attacker to
    cause a denial of service via a crafted PDF file.
    (CVE-2020-16295)

  - A buffer overflow vulnerability in GetNumWrongData() in
    contrib/lips4/gdevlips.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a
    denial of service via a crafted PDF file.
    (CVE-2020-16296)

  - A buffer overflow vulnerability in
    FloydSteinbergDitheringC() in contrib/gdevbjca.c of
    Artifex Software GhostScript v9.50 allows a remote
    attacker to cause a denial of service via a crafted PDF
    file. (CVE-2020-16297)

  - A buffer overflow vulnerability in mj_color_correct()
    in contrib/japanese/gdevmjc.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a
    denial of service via a crafted PDF file.
    (CVE-2020-16298)

  - A buffer overflow vulnerability in tiff12_print_page()
    in devices/gdevtfnx.c of Artifex Software GhostScript
    v9.50 allows a remote attacker to cause a denial of
    service via a crafted PDF file. (CVE-2020-16300)

  - A buffer overflow vulnerability in okiibm_print_page1()
    in devices/gdevokii.c of Artifex Software GhostScript
    v9.50 allows a remote attacker to cause a denial of
    service via a crafted PDF file. (CVE-2020-16301)

  - A buffer overflow vulnerability in GetNumSameData() in
    contrib/lips4/gdevlips.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a
    denial of service via a crafted PDF file.
    (CVE-2020-17538)

  - A buffer overflow vulnerability in pcx_write_rle() in
    contrib/japanese/gdev10v.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a
    denial of service via a crafted PDF file.
    (CVE-2020-16305)

  - A buffer overflow vulnerability in p_print_image() in
    devices/gdevcdj.c of Artifex Software GhostScript v9.50
    allows a remote attacker to cause a denial of service
    via a crafted PDF file. (CVE-2020-16308)

  - A buffer overflow vulnerability in
    lxm5700m_print_page() in devices/gdevlxm.c of Artifex
    Software GhostScript v9.50 allows a remote attacker to
    cause a denial of service via a crafted eps file.
    (CVE-2020-16309)

  - A division by zero vulnerability in dot24_print_page()
    in devices/gdevdm24.c of Artifex Software GhostScript
    v9.50 allows a remote attacker to cause a denial of
    service via a crafted PDF file. (CVE-2020-16310)

  - A buffer overflow vulnerability in lprn_is_black() in
    contrib/lips4/gdevlprn.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to cause a
    denial of service via a crafted PDF file.
    (CVE-2020-16287)

  - A buffer overflow vulnerability in contrib/gdevdj9.c of
    Artifex Software GhostScript v9.50 allows a remote
    attacker to cause a denial of service via a crafted PDF
    file. (CVE-2020-16291)

  - A buffer overflow vulnerability in
    jetp3852_print_page() in devices/gdev3852.c of Artifex
    Software GhostScript v9.50 allows a remote attacker to
    escalate privileges via a crafted PDF file.
    (CVE-2020-16302)

  - psi/ztoken.c in Artifex Ghostscript 9.21 mishandles
    references to the scanner state structure, which allows
    remote attackers to cause a denial of service
    (application crash) or possibly have unspecified other
    impact via a crafted PostScript document, related to an
    out-of-bounds read in the igc_reloc_struct_ptr function
    in psi/igc.c.(CVE-2017-11714)

  - The pdf14_open function in base/gdevp14.c in Artifex
    Software, Inc. Ghostscript 9.20 allows remote attackers
    to cause a denial of service (use-after-free and
    application crash) via a crafted file that is
    mishandled in the color management
    module.(CVE-2016-10217)

  - The pdf14_pop_transparency_group function in
    base/gdevp14.c in the PDF Transparency module in
    Artifex Software, Inc. Ghostscript 9.20 allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) via a crafted
    file.(CVE-2016-10218)

  - The intersect function in base/gxfill.c in Artifex
    Software, Inc. Ghostscript 9.20 allows remote attackers
    to cause a denial of service (divide-by-zero error and
    application crash) via a crafted file.(CVE-2016-10219)

  - The gs_makewordimagedevice function in base/gsdevmem.c
    in Artifex Software, Inc. Ghostscript 9.20 allows
    remote attackers to cause a denial of service (NULL
    pointer dereference and application crash) via a
    crafted file that is mishandled in the PDF Transparency
    module.(CVE-2016-10220)

  - The fill_threshhold_buffer function in
    base/gxht_thresh.c in Artifex Software, Inc.
    Ghostscript 9.20 allows remote attackers to cause a
    denial of service (heap-based buffer overflow and
    application crash) or possibly have unspecified other
    impact via a crafted PostScript
    document.(CVE-2016-10317)

  - The mem_get_bits_rectangle function in base/gdevmem.c
    in Artifex Software, Inc. Ghostscript 9.20 allows
    remote attackers to cause a denial of service (NULL
    pointer dereference and application crash) via a
    crafted file.(CVE-2017-5951)

  - The Ins_IP function in base/ttinterp.c in Artifex
    Ghostscript GhostXPS 9.21 allows remote attackers to
    cause a denial of service (use-after-free and
    application crash) or possibly have unspecified other
    impact via a crafted document.(CVE-2017-9612)

  - The Ins_MDRP function in base/ttinterp.c in Artifex
    Ghostscript GhostXPS 9.21 allows remote attackers to
    cause a denial of service (heap-based buffer over-read
    and application crash) or possibly have unspecified
    other impact via a crafted document.(CVE-2017-9726)

  - The gx_ttfReader__Read function in base/gxttfb.c in
    Artifex Ghostscript GhostXPS 9.21 allows remote
    attackers to cause a denial of service (heap-based
    buffer over-read and application crash) or possibly
    have unspecified other impact via a crafted
    document.(CVE-2017-9727)

  - The Ins_JMPR function in base/ttinterp.c in Artifex
    Ghostscript GhostXPS 9.21 allows remote attackers to
    cause a denial of service (heap-based buffer over-read
    and application crash) or possibly have unspecified
    other impact via a crafted document.(CVE-2017-9739)

  - The gs_alloc_ref_array function in psi/ialloc.c in
    Artifex Ghostscript 9.21 allows remote attackers to
    cause a denial of service (heap-based buffer overflow
    and application crash) or possibly have unspecified
    other impact via a crafted PostScript document. This is
    related to a lack of an integer overflow check in
    base/gsalloc.c.(CVE-2017-9835)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1476
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62c9f519");
  script_set_attribute(attribute:"solution", value:
"Update the affected ghostscript packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ghostscript-cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["ghostscript-9.07-31.6.h20.eulerosv2r7",
        "ghostscript-cups-9.07-31.6.h20.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript");
}
