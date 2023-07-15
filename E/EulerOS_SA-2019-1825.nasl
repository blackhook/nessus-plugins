#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128194);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2018-12886"
  );

  script_name(english:"EulerOS 2.0 SP8 : gcc (EulerOS-SA-2019-1825)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the gcc packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - The gcc package contains the GNU Compiler Collection
    version 4.8.You'll need this package in order to
    compile C code.

  - Security fix(es):

  - stack_protect_prologue in cfgexpand.c and
    stack_protect_epilogue in function.c in GNU Compiler
    Collection (GCC) 4.1 through 8 (under certain
    circumstances) generate instruction sequences when
    targeting ARM targets that spill the address of the
    stack protector guard, which allows an attacker to
    bypass the protection of -fstack-protector,
    -fstack-protector-all, -fstack-protector-strong, and
    -fstack-protector-explicit against stack overflow by
    controlling what the stack canary is compared
    against.(CVE-2018-12886)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1825
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd2826e2");
  script_set_attribute(attribute:"solution", value:
"Update the affected gcc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gcc-objc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libasan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libatomic-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libitm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["cpp-7.3.0-20190804.h16.eulerosv2r8",
        "gcc-7.3.0-20190804.h16.eulerosv2r8",
        "gcc-c++-7.3.0-20190804.h16.eulerosv2r8",
        "gcc-gfortran-7.3.0-20190804.h16.eulerosv2r8",
        "gcc-objc++-7.3.0-20190804.h16.eulerosv2r8",
        "gcc-objc-7.3.0-20190804.h16.eulerosv2r8",
        "libasan-7.3.0-20190804.h16.eulerosv2r8",
        "libatomic-7.3.0-20190804.h16.eulerosv2r8",
        "libatomic-static-7.3.0-20190804.h16.eulerosv2r8",
        "libgcc-7.3.0-20190804.h16.eulerosv2r8",
        "libgfortran-7.3.0-20190804.h16.eulerosv2r8",
        "libgomp-7.3.0-20190804.h16.eulerosv2r8",
        "libitm-7.3.0-20190804.h16.eulerosv2r8",
        "libitm-devel-7.3.0-20190804.h16.eulerosv2r8",
        "libobjc-7.3.0-20190804.h16.eulerosv2r8",
        "libstdc++-7.3.0-20190804.h16.eulerosv2r8",
        "libstdc++-devel-7.3.0-20190804.h16.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc");
}
