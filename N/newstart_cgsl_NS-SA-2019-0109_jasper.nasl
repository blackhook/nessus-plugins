#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0109. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127345);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2015-5203",
    "CVE-2015-5221",
    "CVE-2016-1577",
    "CVE-2016-1867",
    "CVE-2016-2089",
    "CVE-2016-2116",
    "CVE-2016-8654",
    "CVE-2016-8690",
    "CVE-2016-8691",
    "CVE-2016-8692",
    "CVE-2016-8693",
    "CVE-2016-8883",
    "CVE-2016-8884",
    "CVE-2016-8885",
    "CVE-2016-9262",
    "CVE-2016-9387",
    "CVE-2016-9388",
    "CVE-2016-9389",
    "CVE-2016-9390",
    "CVE-2016-9391",
    "CVE-2016-9392",
    "CVE-2016-9393",
    "CVE-2016-9394",
    "CVE-2016-9560",
    "CVE-2016-9583",
    "CVE-2016-9591",
    "CVE-2016-9600",
    "CVE-2016-10248",
    "CVE-2016-10249",
    "CVE-2016-10251"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : jasper Multiple Vulnerabilities (NS-SA-2019-0109)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has jasper packages installed that are affected by multiple
vulnerabilities:

  - JasPer before version 2.0.10 is vulnerable to a null
    pointer dereference was found in the decoded creation of
    JPEG 2000 image files. A specially crafted file could
    cause an application using JasPer to crash.
    (CVE-2016-9600)

  - A use-after-free flaw was found in the way JasPer,
    before version 2.0.12, decode certain JPEG 2000 image
    files. A specially crafted file could cause an
    application using JasPer to crash. (CVE-2016-9591)

  - An out-of-bounds heap read vulnerability was found in
    the jpc_pi_nextpcrl() function of jasper before 2.0.6
    when processing crafted input. (CVE-2016-9583)

  - A heap-buffer overflow vulnerability was found in QMFB
    code in JPC codec caused by buffer being allocated with
    too small size. jasper versions before 2.0.0 are
    affected. (CVE-2016-8654)

  - Stack-based buffer overflow in the jpc_tsfb_getbands2
    function in jpc_tsfb.c in JasPer before 1.900.30 allows
    remote attackers to have unspecified impact via a
    crafted image. (CVE-2016-9560)

  - Multiple integer overflows in the (1) jas_realloc
    function in base/jas_malloc.c and (2) mem_resize
    function in base/jas_stream.c in JasPer before 1.900.22
    allow remote attackers to cause a denial of service via
    a crafted image, which triggers use after free
    vulnerabilities. (CVE-2016-9262)

  - Integer overflow in the jpc_pi_nextcprl function in
    jpc_t2cod.c in JasPer before 1.900.20 allows remote
    attackers to have unspecified impact via a crafted file,
    which triggers use of an uninitialized value.
    (CVE-2016-10251)

  - The jpc_pi_nextrpcl function in jpc_t2cod.c in JasPer
    before 1.900.17 allows remote attackers to cause a
    denial of service (assertion failure) via a crafted
    file. (CVE-2016-9393)

  - The calcstepsizes function in jpc_dec.c in JasPer before
    1.900.17 allows remote attackers to cause a denial of
    service (assertion failure) via a crafted file.
    (CVE-2016-9392)

  - The jas_seq2d_create function in jas_seq.c in JasPer
    before 1.900.17 allows remote attackers to cause a
    denial of service (assertion failure) via a crafted
    file. (CVE-2016-9394)

  - The jpc_bitstream_getbits function in jpc_bs.c in JasPer
    before 2.0.10 allows remote attackers to cause a denial
    of service (assertion failure) via a very large integer.
    (CVE-2016-9391)

  - The ras_getcmap function in ras_dec.c in JasPer before
    1.900.14 allows remote attackers to cause a denial of
    service (assertion failure) via a crafted image file.
    (CVE-2016-9388)

  - The jpc_irct and jpc_iict functions in jpc_mct.c in
    JasPer before 1.900.14 allow remote attackers to cause a
    denial of service (assertion failure). (CVE-2016-9389)

  - The jas_seq2d_create function in jas_seq.c in JasPer
    before 1.900.14 allows remote attackers to cause a
    denial of service (assertion failure) via a crafted
    image file. (CVE-2016-9390)

  - Integer overflow in the jpc_dec_process_siz function in
    libjasper/jpc/jpc_dec.c in JasPer before 1.900.13 allows
    remote attackers to have unspecified impact via a
    crafted file, which triggers an assertion failure.
    (CVE-2016-9387)

  - Integer overflow in the jpc_dec_tiledecode function in
    jpc_dec.c in JasPer before 1.900.12 allows remote
    attackers to have unspecified impact via a crafted image
    file, which triggers a heap-based buffer overflow.
    (CVE-2016-10249)

  - The jpc_tsfb_synthesize function in jpc_tsfb.c in JasPer
    before 1.900.9 allows remote attackers to cause a denial
    of service (NULL pointer dereference) via vectors
    involving an empty sequence. (CVE-2016-10248)

  - The jpc_dec_tiledecode function in jpc_dec.c in JasPer
    before 1.900.8 allows remote attackers to cause a denial
    of service (assertion failure) via a crafted file.
    (CVE-2016-8883)

  - The jpc_dec_process_siz function in
    libjasper/jpc/jpc_dec.c in JasPer before 1.900.4 allows
    remote attackers to cause a denial of service (divide-
    by-zero error and application crash) via a crafted YRsiz
    value in a BMP image to the imginfo command.
    (CVE-2016-8692)

  - The bmp_getdata function in libjasper/bmp/bmp_dec.c in
    JasPer 1.900.5 allows remote attackers to cause a denial
    of service (NULL pointer dereference) by calling the
    imginfo command with a crafted BMP image. NOTE: this
    vulnerability exists because of an incomplete fix for
    CVE-2016-8690. (CVE-2016-8884)

  - Double free vulnerability in the mem_close function in
    jas_stream.c in JasPer before 1.900.10 allows remote
    attackers to cause a denial of service (crash) or
    possibly execute arbitrary code via a crafted BMP image
    to the imginfo command. (CVE-2016-8693)

  - The bmp_getdata function in libjasper/bmp/bmp_dec.c in
    JasPer before 1.900.5 allows remote attackers to cause a
    denial of service (NULL pointer dereference) via a
    crafted BMP image in an imginfo command. (CVE-2016-8690)

  - The bmp_getdata function in libjasper/bmp/bmp_dec.c in
    JasPer before 1.900.9 allows remote attackers to cause a
    denial of service (NULL pointer dereference) by calling
    the imginfo command with a crafted BMP image.
    (CVE-2016-8885)

  - The jpc_dec_process_siz function in
    libjasper/jpc/jpc_dec.c in JasPer before 1.900.4 allows
    remote attackers to cause a denial of service (divide-
    by-zero error and application crash) via a crafted XRsiz
    value in a BMP image to the imginfo command.
    (CVE-2016-8691)

  - Double free vulnerability in the jas_iccattrval_destroy
    function in JasPer 1.900.1 and earlier allows remote
    attackers to cause a denial of service (crash) or
    possibly execute arbitrary code via a crafted ICC color
    profile in a JPEG 2000 image file, a different
    vulnerability than CVE-2014-8137. (CVE-2016-1577)

  - Memory leak in the jas_iccprof_createfrombuf function in
    JasPer 1.900.1 and earlier allows remote attackers to
    cause a denial of service (memory consumption) via a
    crafted ICC color profile in a JPEG 2000 image file.
    (CVE-2016-2116)

  - The jas_matrix_clip function in jas_seq.c in JasPer
    1.900.1 allows remote attackers to cause a denial of
    service (invalid read and application crash) via a
    crafted JPEG 2000 image. (CVE-2016-2089)

  - Double free vulnerability in the jasper_image_stop_load
    function in JasPer 1.900.17 allows remote attackers to
    cause a denial of service (crash) via a crafted JPEG
    2000 image file. (CVE-2015-5203)

  - The jpc_pi_nextcprl function in JasPer 1.900.1 allows
    remote attackers to cause a denial of service (out-of-
    bounds read and application crash) via a crafted JPEG
    2000 image. (CVE-2016-1867)

  - Use-after-free vulnerability in the mif_process_cmpt
    function in libjasper/mif/mif_cod.c in the JasPer
    JPEG-2000 library before 1.900.2 allows remote attackers
    to cause a denial of service (crash) via a crafted JPEG
    2000 image file. (CVE-2015-5221)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0109");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL jasper packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9583");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "jasper-1.900.1-21.el6_9",
    "jasper-libs-1.900.1-21.el6_9"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jasper");
}
