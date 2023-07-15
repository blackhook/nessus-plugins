#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135512);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2015-5276"
  );

  script_name(english:"EulerOS 2.0 SP3 : gcc (EulerOS-SA-2020-1383)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the gcc packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerability :

  - The std::random_device class in libstdc++ in the GNU
    Compiler Collection (aka GCC) before 4.9.4 does not
    properly handle short reads from blocking sources,
    which makes it easier for context-dependent attackers
    to predict the random values via unspecified
    vectors.(CVE-2015-5276)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1383
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca2a6d0e");
  script_set_attribute(attribute:"solution", value:
"Update the affected gcc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gcc-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gcc-objc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libasan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libatomic-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgnat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libitm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["cpp-4.8.5-4.h12",
        "gcc-4.8.5-4.h12",
        "gcc-c++-4.8.5-4.h12",
        "gcc-gfortran-4.8.5-4.h12",
        "gcc-gnat-4.8.5-4.h12",
        "gcc-go-4.8.5-4.h12",
        "gcc-objc++-4.8.5-4.h12",
        "gcc-objc-4.8.5-4.h12",
        "libasan-4.8.5-4.h12",
        "libatomic-4.8.5-4.h12",
        "libatomic-static-4.8.5-4.h12",
        "libgcc-4.8.5-4.h12",
        "libgfortran-4.8.5-4.h12",
        "libgnat-4.8.5-4.h12",
        "libgnat-devel-4.8.5-4.h12",
        "libgo-4.8.5-4.h12",
        "libgo-devel-4.8.5-4.h12",
        "libgomp-4.8.5-4.h12",
        "libitm-4.8.5-4.h12",
        "libitm-devel-4.8.5-4.h12",
        "libobjc-4.8.5-4.h12",
        "libquadmath-4.8.5-4.h12",
        "libquadmath-devel-4.8.5-4.h12",
        "libstdc++-4.8.5-4.h12",
        "libstdc++-devel-4.8.5-4.h12",
        "libstdc++-docs-4.8.5-4.h12"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc");
}
