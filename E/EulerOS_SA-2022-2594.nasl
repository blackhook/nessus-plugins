#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165969);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_cve_id(
    "CVE-2021-4166",
    "CVE-2021-4192",
    "CVE-2021-4193",
    "CVE-2022-0213",
    "CVE-2022-0261",
    "CVE-2022-0318",
    "CVE-2022-0319",
    "CVE-2022-0351",
    "CVE-2022-0359",
    "CVE-2022-0361",
    "CVE-2022-0368",
    "CVE-2022-0392",
    "CVE-2022-0408",
    "CVE-2022-0413",
    "CVE-2022-0417",
    "CVE-2022-0443",
    "CVE-2022-0554",
    "CVE-2022-0572",
    "CVE-2022-0685",
    "CVE-2022-0714",
    "CVE-2022-0729",
    "CVE-2022-0943",
    "CVE-2022-1154",
    "CVE-2022-1616",
    "CVE-2022-1620",
    "CVE-2022-1621",
    "CVE-2022-1629",
    "CVE-2022-1674",
    "CVE-2022-1733",
    "CVE-2022-1735",
    "CVE-2022-1771",
    "CVE-2022-1785",
    "CVE-2022-1796",
    "CVE-2022-1851",
    "CVE-2022-1897",
    "CVE-2022-1898",
    "CVE-2022-1927",
    "CVE-2022-1942",
    "CVE-2022-1968",
    "CVE-2022-2000"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.0 : vim (EulerOS-SA-2022-2594)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the vim packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - vim is vulnerable to Out-of-bounds Read (CVE-2021-4166, CVE-2021-4193)

  - vim is vulnerable to Use After Free (CVE-2021-4192)

  - vim is vulnerable to Heap-based Buffer Overflow (CVE-2022-0213)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-0261, CVE-2022-0359,
    CVE-2022-0361, CVE-2022-0572, CVE-2022-1942)

  - Heap-based Buffer Overflow in vim/vim prior to 8.2. (CVE-2022-0318)

  - Out-of-bounds Read in vim/vim prior to 8.2. (CVE-2022-0319)

  - Access of Memory Location Before Start of Buffer in GitHub repository vim/vim prior to 8.2.
    (CVE-2022-0351)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 8.2. (CVE-2022-0368, CVE-2022-1851)

  - Heap-based Buffer Overflow in GitHub repository vim prior to 8.2. (CVE-2022-0392)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-0408)

  - Use After Free in GitHub repository vim/vim prior to 8.2. (CVE-2022-0413, CVE-2022-0443, CVE-2022-1898,
    CVE-2022-1968)

  - Heap-based Buffer Overflow GitHub repository vim/vim prior to 8.2. (CVE-2022-0417)

  - Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2. (CVE-2022-0554)

  - Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.4418. (CVE-2022-0685)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.4436. (CVE-2022-0714)

  - Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.4440. (CVE-2022-0729)

  - Heap-based Buffer Overflow occurs in vim in GitHub repository vim/vim prior to 8.2.4563. (CVE-2022-0943)

  - Use after free in utf_ptr2char in GitHub repository vim/vim prior to 8.2.4646. (CVE-2022-1154)

  - Use after free in append_command in GitHub repository vim/vim prior to 8.2.4895. This vulnerability is
    capable of crashing software, Bypass Protection Mechanism, Modify Memory, and possible remote execution
    (CVE-2022-1616)

  - NULL Pointer Dereference in function vim_regexec_string at regexp.c:2729 in GitHub repository vim/vim
    prior to 8.2.4901. NULL Pointer Dereference in function vim_regexec_string at regexp.c:2729 allows
    attackers to cause a denial of service (application crash) via a crafted input. (CVE-2022-1620)

  - Heap buffer overflow in vim_strncpy find_word in GitHub repository vim/vim prior to 8.2.4919. This
    vulnerability is capable of crashing software, Bypass Protection Mechanism, Modify Memory, and possible
    remote execution (CVE-2022-1621)

  - Buffer Over-read in function find_next_quote in GitHub repository vim/vim prior to 8.2.4925. This
    vulnerabilities are capable of crashing software, Modify Memory, and possible remote execution
    (CVE-2022-1629)

  - NULL Pointer Dereference in function vim_regexec_string at regexp.c:2733 in GitHub repository vim/vim
    prior to 8.2.4938. NULL Pointer Dereference in function vim_regexec_string at regexp.c:2733 allows
    attackers to cause a denial of service (application crash) via a crafted input. (CVE-2022-1674)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.4968. (CVE-2022-1733)

  - Classic Buffer Overflow in GitHub repository vim/vim prior to 8.2.4969. (CVE-2022-1735)

  - Uncontrolled Recursion in GitHub repository vim/vim prior to 8.2.4975. (CVE-2022-1771)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.4977. (CVE-2022-1785)

  - Use After Free in GitHub repository vim/vim prior to 8.2.4979. (CVE-2022-1796)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 8.2. (CVE-2022-1897, CVE-2022-2000)

  - Buffer Over-read in GitHub repository vim/vim prior to 8.2. (CVE-2022-1927)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2594
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b693649");
  script_set_attribute(attribute:"solution", value:
"Update the affected vim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1927");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-X11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "vim-X11-8.1.450-1.h31.eulerosv2r8",
  "vim-common-8.1.450-1.h31.eulerosv2r8",
  "vim-enhanced-8.1.450-1.h31.eulerosv2r8",
  "vim-filesystem-8.1.450-1.h31.eulerosv2r8",
  "vim-minimal-8.1.450-1.h31.eulerosv2r8"
];

foreach (var pkg in pkgs)
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim");
}
