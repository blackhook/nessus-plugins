#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135661);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/06");

  script_cve_id(
    "CVE-2016-7976",
    "CVE-2016-9601",
    "CVE-2017-7885",
    "CVE-2017-7975",
    "CVE-2017-7976",
    "CVE-2017-9216",
    "CVE-2018-11645",
    "CVE-2018-19478",
    "CVE-2019-10216",
    "CVE-2019-14811",
    "CVE-2019-14812",
    "CVE-2019-14813",
    "CVE-2019-14817"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.2 : ghostscript (EulerOS-SA-2020-1499)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ghostscript package installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - The PS Interpreter in Ghostscript 9.18 and 9.20 allows
    remote attackers to execute arbitrary code via crafted
    userparams.(CVE-2016-7976)

  - psi/zfile.c in Artifex Ghostscript before 9.21rc1
    permits the status command even if -dSAFER is used,
    which might allow remote attackers to determine the
    existence and size of arbitrary files, a similar issue
    to CVE-2016-7977.(CVE-2018-11645)

  - A flaw was found in the .pdfexectoken and other
    procedures where it did not properly secure its
    privileged calls, enabling scripts to bypass `-dSAFER`
    restrictions. A specially crafted PostScript file could
    disable security protection and then have access to the
    file system, or execute arbitrary
    commands.(CVE-2019-14817)

  - A flaw was found in the setsystemparams procedure where
    it did not properly secure its privileged calls,
    enabling scripts to bypass `-dSAFER` restrictions. A
    specially crafted PostScript file could disable
    security protection and then have access to the file
    system, or execute arbitrary commands.(CVE-2019-14813)

  - A flaw was found in the .setuserparams2 procedure where
    it did not properly secure its privileged calls,
    enabling scripts to bypass `-dSAFER` restrictions. A
    specially crafted PostScript file could disable
    security protection and then have access to the file
    system, or execute arbitrary commands.(CVE-2019-14812)

  - A flaw was found in the .pdf_hook_DSC_Creator procedure
    where it did not properly secure its privileged calls,
    enabling scripts to bypass `-dSAFER` restrictions. A
    specially crafted PostScript file could disable
    security protection and then have access to the file
    system, or execute arbitrary commands.(CVE-2019-14811)

  - libjbig2dec.a in Artifex jbig2dec 0.13, as used in
    MuPDF and Ghostscript, has a NULL pointer dereference
    in the jbig2_huffman_get function in jbig2_huffman.c.
    For example, the jbig2dec utility will crash
    (segmentation fault) when parsing an invalid
    file.(CVE-2017-9216)

  - Artifex jbig2dec 0.13, as used in Ghostscript, allows
    out-of-bounds writes because of an integer overflow in
    the jbig2_build_huffman_table function in
    jbig2_huffman.c during operations on a crafted JBIG2
    file, leading to a denial of service (application
    crash) or possibly execution of arbitrary
    code.(CVE-2017-7975)

  - Artifex jbig2dec 0.13 has a heap-based buffer over-read
    leading to denial of service (application crash) or
    disclosure of sensitive information from process
    memory, because of an integer overflow in the
    jbig2_decode_symbol_dict function in
    jbig2_symbol_dict.c in libjbig2dec.a during operation
    on a crafted .jb2 file.(CVE-2017-7885)

  - Artifex jbig2dec 0.13 allows out-of-bounds writes and
    reads because of an integer overflow in the
    jbig2_image_compose function in jbig2_image.c during
    operations on a crafted .jb2 file, leading to a denial
    of service (application crash) or disclosure of
    sensitive information from process
    memory.(CVE-2017-7976)

  - ghostscript before version 9.21 is vulnerable to a heap
    based buffer overflow that was found in the ghostscript
    jbig2_decode_gray_scale_image function which is used to
    decode halftone segments in a JBIG2 image. A document
    (PostScript or PDF) with an embedded, specially
    crafted, jbig2 image could trigger a segmentation fault
    in ghostscript.(CVE-2016-9601)

  - In Artifex Ghostscript before 9.26, a carefully crafted
    PDF file can trigger an extremely long running
    computation when parsing the file.(CVE-2018-19478)

  - It was found that the .buildfont1 procedure did not
    properly secure its privileged calls, enabling scripts
    to bypass `-dSAFER` restrictions. An attacker could
    abuse this flaw by creating a specially crafted
    PostScript file that could escalate privileges and
    access files outside of restricted
    areas.(CVE-2019-10216)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1499
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce7df4f5");
  script_set_attribute(attribute:"solution", value:
"Update the affected ghostscript packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["ghostscript-9.07-31.6.h13.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript");
}
