#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118419);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/03");

  script_cve_id("CVE-2017-11671");

  script_name(english:"EulerOS Virtualization 2.5.0 : gcc (EulerOS-SA-2018-1331)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the gcc packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - The gcc package contains the GNU Compiler Collection
    version 4.8.You'll need this package in order to
    compile C code.

  - Security fix(es):

  - Under certain circumstances, the ix86_expand_builtin
    function in i386.c in GNU Compiler Collection (GCC)
    version 4.6, 4.7, 4.8, 4.9, 5 before 5.5, and 6 before
    6.4 will generate instruction sequences that clobber
    the status flag of the RDRAND and RDSEED intrinsics
    before it can be read, potentially causing failures of
    these instructions to go unreported. This could
    potentially lead to less randomness in random number
    generation.(CVE-2017-11671)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1331
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f770da01");
  script_set_attribute(attribute:"solution", value:
"Update the affected gcc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11671");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.5.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "2.5.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.5.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["cpp-4.8.3-10.h3",
        "gcc-4.8.3-10.h3",
        "gcc-c++-4.8.3-10.h3",
        "gcc-gfortran-4.8.3-10.h3",
        "libgcc-4.8.3-10.h3",
        "libgfortran-4.8.3-10.h3",
        "libgomp-4.8.3-10.h3",
        "libquadmath-4.8.3-10.h3",
        "libquadmath-devel-4.8.3-10.h3",
        "libstdc++-4.8.3-10.h3",
        "libstdc++-devel-4.8.3-10.h3"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc");
}
