#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177157);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/13");

  script_cve_id(
    "CVE-2022-1720",
    "CVE-2022-1725",
    "CVE-2022-2124",
    "CVE-2022-2125",
    "CVE-2022-2126",
    "CVE-2022-2175",
    "CVE-2022-2182",
    "CVE-2022-2183",
    "CVE-2022-2206",
    "CVE-2022-2207",
    "CVE-2022-2208",
    "CVE-2022-2210",
    "CVE-2022-2257",
    "CVE-2022-2264",
    "CVE-2022-2284",
    "CVE-2022-2285",
    "CVE-2022-2287",
    "CVE-2022-2289",
    "CVE-2022-2304",
    "CVE-2022-2345",
    "CVE-2022-2571",
    "CVE-2022-2845",
    "CVE-2022-2923",
    "CVE-2022-2980",
    "CVE-2022-3234",
    "CVE-2022-3235",
    "CVE-2022-3256",
    "CVE-2022-3296",
    "CVE-2022-3297",
    "CVE-2022-3324",
    "CVE-2022-3352",
    "CVE-2022-3520",
    "CVE-2022-3705",
    "CVE-2022-4141",
    "CVE-2022-4292",
    "CVE-2023-0049",
    "CVE-2023-0288",
    "CVE-2023-0433"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.0 : vim (EulerOS-SA-2023-2251)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the vim packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - Buffer Over-read in function grab_file_name in GitHub repository vim/vim prior to 8.2.4956. This
    vulnerability is capable of crashing the software, memory modification, and possible remote execution.
    (CVE-2022-1720)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.4959. (CVE-2022-1725)

  - Buffer Over-read in GitHub repository vim/vim prior to 8.2. (CVE-2022-2124, CVE-2022-2175)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-2125, CVE-2022-2182,
    CVE-2022-2207)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 8.2. (CVE-2022-2126, CVE-2022-2183,
    CVE-2022-2206)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.5163. (CVE-2022-2208)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 8.2. (CVE-2022-2210)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 9.0. (CVE-2022-2257, CVE-2022-2287)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0. (CVE-2022-2264, CVE-2022-2284)

  - Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0. (CVE-2022-2285)

  - Use After Free in GitHub repository vim/vim prior to 9.0. (CVE-2022-2289)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0. (CVE-2022-2304)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0046. (CVE-2022-2345)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0101. (CVE-2022-2571)

  - Buffer Over-read in GitHub repository vim/vim prior to 9.0.0218. (CVE-2022-2845)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0240. (CVE-2022-2923)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0259. (CVE-2022-2980)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0483. (CVE-2022-3234)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0490. (CVE-2022-3235)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0530. (CVE-2022-3256)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0577. (CVE-2022-3296)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0579. (CVE-2022-3297)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0598. (CVE-2022-3324)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0614. (CVE-2022-3352)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0765. (CVE-2022-3520)

  - A vulnerability was found in vim and classified as problematic. Affected by this issue is the function
    qf_update_buffer of the file quickfix.c of the component autocmd Handler. The manipulation leads to use
    after free. The attack may be launched remotely. Upgrading to version 9.0.0805 is able to address this
    issue. The name of the patch is d0fab10ed2a86698937e3c3fed2f10bd9bb5e731. It is recommended to upgrade the
    affected component. The identifier of this vulnerability is VDB-212324. (CVE-2022-3705)

  - Heap based buffer overflow in vim/vim 9.0.0946 and below by allowing an attacker to CTRL-W gf in the
    expression used in the RHS of the substitute command. (CVE-2022-4141)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0882. (CVE-2022-4292)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.1143. (CVE-2023-0049)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1189. (CVE-2023-0288)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1225. (CVE-2023-0433)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2251
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5602fd3f");
  script_set_attribute(attribute:"solution", value:
"Update the affected vim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2345");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3520");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-X11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "vim-X11-8.1.450-1.h47.eulerosv2r8",
  "vim-common-8.1.450-1.h47.eulerosv2r8",
  "vim-enhanced-8.1.450-1.h47.eulerosv2r8",
  "vim-filesystem-8.1.450-1.h47.eulerosv2r8",
  "vim-minimal-8.1.450-1.h47.eulerosv2r8"
];

foreach (var pkg in pkgs)
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim");
}
