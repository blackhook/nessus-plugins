#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136217);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/06");

  script_cve_id(
    "CVE-2018-20796",
    "CVE-2019-6488",
    "CVE-2019-9192",
    "CVE-2020-10029"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : glibc (EulerOS-SA-2020-1514)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glibc packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The glibc package contains standard libraries which are
    used by multiple programs on the system. In order to
    save disk space and memory, as well as to make
    upgrading easier, common system code is kept in one
    place and shared between programs. This particular
    package contains the most important sets of shared
    libraries: the standard C library and the standard math
    library. Without these two libraries, a Linux system
    will not function.Security Fix(es):The string component
    in the GNU C Library (aka glibc or libc6) through 2.28,
    when running on the x32 architecture, incorrectly
    attempts to use a 64-bit register for size_t in
    assembly codes, which can lead to a segmentation fault
    or possibly unspecified other impact, as demonstrated
    by a crash in __memmove_avx_unaligned_erms in
    sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S
    during a memcpy.(CVE-2019-6488)** DISPUTED ** In the
    GNU C Library (aka glibc or libc6) through 2.29,
    check_dst_limits_calc_pos_1 in posix/regexec.c has
    Uncontrolled Recursion, as demonstrated by
    '(|)(\\1\\1)*' in grep, a different issue than
    CVE-2018-20796. NOTE: the software maintainer disputes
    that this is a vulnerability because the behavior
    occurs only with a crafted pattern.(CVE-2019-9192)In
    the GNU C Library (aka glibc or libc6) through 2.29,
    check_dst_limits_calc_pos_1 in posix/regexec.c has
    Uncontrolled Recursion, as demonstrated by
    '(\227|)(\\1\\1|t1|\\\2537)+' in
    grep.(CVE-2018-20796)The GNU C Library (aka glibc or
    libc6) before 2.32 could overflow an on-stack buffer
    during range reduction if an input to an 80-bit long
    double function contains a non-canonical bit pattern, a
    seen when passing a 0x5d414141414141410000 value to
    sinl on x86 targets. This is related to
    sysdeps/ieee754/ldbl-96/e_rem_pio2l.c.(CVE-2020-10029)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1514
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6e042d2");
  script_set_attribute(attribute:"solution", value:
"Update the affected glibc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6488");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-all-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libnsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["glibc-2.28-9.h37",
        "glibc-all-langpacks-2.28-9.h37",
        "glibc-common-2.28-9.h37",
        "glibc-devel-2.28-9.h37",
        "glibc-headers-2.28-9.h37",
        "libnsl-2.28-9.h37",
        "nscd-2.28-9.h37"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
