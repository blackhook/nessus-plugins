#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145157);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2017-10686",
    "CVE-2017-11111",
    "CVE-2017-17811",
    "CVE-2017-17813",
    "CVE-2017-17814",
    "CVE-2017-17816",
    "CVE-2017-17817",
    "CVE-2017-17818",
    "CVE-2017-17820",
    "CVE-2018-8881",
    "CVE-2018-8882",
    "CVE-2018-19214",
    "CVE-2018-19215"
  );

  script_name(english:"EulerOS 2.0 SP3 : nasm (EulerOS-SA-2021-1100)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the nasm package installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - Netwide Assembler (NASM) 2.14rc15 has a heap-based
    buffer over-read in expand_mmac_params in asm/preproc.c
    for insufficient input.(CVE-2018-19214)

  - Netwide Assembler (NASM) 2.14rc16 has a heap-based
    buffer over-read in expand_mmac_params in asm/preproc.c
    for the special cases of the % and $ and !
    characters.(CVE-2018-19215)

  - Netwide Assembler (NASM) 2.13.02rc2 has a heap-based
    buffer over-read in the function tokenize in
    asm/preproc.c, related to an unterminated
    string.(CVE-2018-8881)

  - Netwide Assembler (NASM) 2.13.02rc2 has a stack-based
    buffer under-read in the function ieee_shr in
    asm/float.c via a large shift value.(CVE-2018-8882)

  - In Netwide Assembler (NASM) 2.14rc0, there are multiple
    heap use after free vulnerabilities in the tool nasm.
    The related heap is allocated in the token() function
    and freed in the detoken() function (called by
    pp_getline()) - it is used again at multiple positions
    later that could cause multiple damages. For example,
    it causes a corrupted double-linked list in detoken(),
    a double free or corruption in delete_Token(), and an
    out-of-bounds write in detoken(). It has a high
    possibility to lead to a remote code execution
    attack.(CVE-2017-10686)

  - In Netwide Assembler (NASM) 2.14rc0, preproc.c allows
    remote attackers to cause a denial of service
    (heap-based buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    file.(CVE-2017-11111)

  - In Netwide Assembler (NASM) 2.14rc0, there is a
    heap-based buffer over-read that will cause a remote
    denial of service attack, related to a while loop in
    paste_tokens in asm/preproc.c.(CVE-2017-17818)

  - In Netwide Assembler (NASM) 2.14rc0, there is a
    heap-based buffer overflow that will cause a remote
    denial of service attack, related to a strcpy in
    paste_tokens in asm/preproc.c, a similar issue to
    CVE-2017-11111.(CVE-2017-17811)

  - In Netwide Assembler (NASM) 2.14rc0, there is a
    use-after-free in the pp_list_one_macro function in
    asm/preproc.c that will cause a remote denial of
    service attack, related to mishandling of line-syntax
    errors.(CVE-2017-17813)

  - In Netwide Assembler (NASM) 2.14rc0, there is a
    use-after-free in do_directive in asm/preproc.c that
    will cause a remote denial of service
    attack.(CVE-2017-17814)

  - In Netwide Assembler (NASM) 2.14rc0, there is a
    use-after-free in pp_getline in asm/preproc.c that will
    cause a remote denial of service
    attack.(CVE-2017-17816)

  - In Netwide Assembler (NASM) 2.14rc0, there is a
    use-after-free in pp_verror in asm/preproc.c that will
    cause a remote denial of service
    attack.(CVE-2017-17817)

  - In Netwide Assembler (NASM) 2.14rc0, there is a
    heap-based buffer over-read that will cause a remote
    denial of service attack, related to a while loop in
    paste_tokens in asm/preproc.c.(CVE-2017-17818)

  - In Netwide Assembler (NASM) 2.14rc0, there is a
    use-after-free in pp_list_one_macro in asm/preproc.c
    that will lead to a remote denial of service attack,
    related to mishandling of operand-type
    errors.(CVE-2017-17820)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1100
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf357410");
  script_set_attribute(attribute:"solution", value:
"Update the affected nasm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8881");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-8882");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nasm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["nasm-2.10.07-7.h3"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nasm");
}
