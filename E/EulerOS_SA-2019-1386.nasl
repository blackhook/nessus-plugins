#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124889);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2015-0235",
    "CVE-2017-16997",
    "CVE-2018-11236",
    "CVE-2018-11237"
  );
  script_bugtraq_id(72325);

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : glibc (EulerOS-SA-2019-1386)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glibc packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - stdlib/canonicalize.c in the GNU C Library (aka glibc
    or libc6) 2.27 and earlier, when processing very long
    pathname arguments to the realpath function, could
    encounter an integer overflow on 32-bit architectures,
    leading to a stack-based buffer overflow and,
    potentially, arbitrary code execution.(CVE-2018-11236)

  - An AVX-512-optimized implementation of the mempcpy
    function in the GNU C Library (aka glibc or libc6) 2.27
    and earlier may write data beyond the target buffer,
    leading to a buffer overflow in
    __mempcpy_avx512_no_vzeroupper.(CVE-2018-11237)

  - elf/dl-load.c in the GNU C Library (aka glibc or libc6)
    2.19 through 2.26 mishandles RPATH and RUNPATH
    containing $ORIGIN for a privileged (setuid or
    AT_SECURE) program, which allows local users to gain
    privileges via a Trojan horse library in the current
    working directory, related to the fillin_rpath and
    decompose_rpath functions. This is associated with
    misinterpretion of an empty RPATH/RUNPATH token as the
    './' directory. NOTE: this configuration of
    RPATH/RUNPATH for a privileged program is apparently
    very uncommon most likely, no such program is shipped
    with any common Linux distribution.(CVE-2017-16997)

  - A heap-based buffer overflow was found in glibc's
    __nss_hostname_digits_dots() function, which is used by
    the gethostbyname() and gethostbyname2() glibc function
    calls. A remote attacker able to make an application
    call either of these functions could use this flaw to
    execute arbitrary code with the permissions of the user
    running the application.(CVE-2015-0235)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1386
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b355490c");
  script_set_attribute(attribute:"solution", value:
"Update the affected glibc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0235");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-11236");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-all-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libnsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["glibc-2.28-9.h1",
        "glibc-all-langpacks-2.28-9.h1",
        "glibc-common-2.28-9.h1",
        "glibc-devel-2.28-9.h1",
        "glibc-headers-2.28-9.h1",
        "libnsl-2.28-9.h1",
        "nscd-2.28-9.h1"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
