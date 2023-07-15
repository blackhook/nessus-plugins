#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164197);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id(
    "CVE-2022-1920",
    "CVE-2022-1921",
    "CVE-2022-1922",
    "CVE-2022-1923",
    "CVE-2022-1924",
    "CVE-2022-1925",
    "CVE-2022-2122"
  );

  script_name(english:"EulerOS 2.0 SP5 : gstreamer1-plugins-good (EulerOS-SA-2022-2269)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the gstreamer1-plugins-good package installed, the EulerOS installation on the remote host
is affected by the following vulnerabilities :

  - Integer overflow in matroskademux element in gst_matroska_demux_add_wvpk_header function which allows a
    heap overwrite while parsing matroska files. Potential for arbitrary code execution through heap
    overwrite. (CVE-2022-1920)

  - Integer overflow in avidemux element in gst_avi_demux_invert function which allows a heap overwrite while
    parsing avi files. Potential for arbitrary code execution through heap overwrite. (CVE-2022-1921)

  - DOS / potential heap overwrite in mkv demuxing using zlib decompression. Integer overflow in matroskademux
    element in gst_matroska_decompress_data function which causes a segfault, or could cause a heap overwrite,
    depending on libc and OS. Depending on the libc used, and the underlying OS capabilities, it could be just
    a segfault or a heap overwrite. If the libc uses mmap for large chunks, and the OS supports mmap, then it
    is just a segfault (because the realloc before the integer overflow will use mremap to reduce the size of
    the chunk, and it will start to write to unmapped memory). However, if using a libc implementation that
    does not use mmap, or if the OS does not support mmap while using libc, then this could result in a heap
    overwrite. (CVE-2022-1922)

  - DOS / potential heap overwrite in mkv demuxing using bzip decompression. Integer overflow in matroskademux
    element in bzip decompression function which causes a segfault, or could cause a heap overwrite, depending
    on libc and OS. Depending on the libc used, and the underlying OS capabilities, it could be just a
    segfault or a heap overwrite. If the libc uses mmap for large chunks, and the OS supports mmap, then it is
    just a segfault (because the realloc before the integer overflow will use mremap to reduce the size of the
    chunk, and it will start to write to unmapped memory). However, if using a libc implementation that does
    not use mmap, or if the OS does not support mmap while using libc, then this could result in a heap
    overwrite. (CVE-2022-1923)

  - DOS / potential heap overwrite in mkv demuxing using lzo decompression. Integer overflow in matroskademux
    element in lzo decompression function which causes a segfault, or could cause a heap overwrite, depending
    on libc and OS. Depending on the libc used, and the underlying OS capabilities, it could be just a
    segfault or a heap overwrite. If the libc uses mmap for large chunks, and the OS supports mmap, then it is
    just a segfault (because the realloc before the integer overflow will use mremap to reduce the size of the
    chunk, and it will start to write to unmapped memory). However, if using a libc implementation that does
    not use mmap, or if the OS does not support mmap while using libc, then this could result in a heap
    overwrite. (CVE-2022-1924)

  - DOS / potential heap overwrite in mkv demuxing using HEADERSTRIP decompression. Integer overflow in
    matroskaparse element in gst_matroska_decompress_data function which causes a heap overflow. Due to
    restrictions on chunk sizes in the matroskademux element, the overflow can't be triggered, however the
    matroskaparse element has no size checks. (CVE-2022-1925)

  - DOS / potential heap overwrite in qtdemux using zlib decompression. Integer overflow in qtdemux element in
    qtdemux_inflate function which causes a segfault, or could cause a heap overwrite, depending on libc and
    OS. Depending on the libc used, and the underlying OS capabilities, it could be just a segfault or a heap
    overwrite. (CVE-2022-2122)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2269
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fe1ae89");
  script_set_attribute(attribute:"solution", value:
"Update the affected gstreamer1-plugins-good packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2122");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gstreamer1-plugins-good");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "gstreamer1-plugins-good-1.10.4-2.h3.eulerosv2r7"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer1-plugins-good");
}
