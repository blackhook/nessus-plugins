#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129223);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-4043",
    "CVE-2015-5180",
    "CVE-2015-8982",
    "CVE-2016-10228",
    "CVE-2016-4429",
    "CVE-2017-12132",
    "CVE-2018-11237",
    "CVE-2019-9169"
  );
  script_bugtraq_id(
    68006
  );

  script_name(english:"EulerOS 2.0 SP3 : glibc (EulerOS-SA-2019-2030)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glibc packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Stack-based buffer overflow in the clntudp_call
    function in sunrpc/clnt_udp.c in the GNU C Library (aka
    glibc or libc6) allows remote servers to cause a denial
    of service (crash) or possibly unspecified other impact
    via a flood of crafted ICMP and UDP
    packets.(CVE-2016-4429)

  - Integer overflow in the strxfrm function in the GNU C
    Library (aka glibc or libc6) before 2.21 allows
    context-dependent attackers to cause a denial of
    service (crash) or possibly execute arbitrary code via
    a long string, which triggers a stack-based buffer
    overflow.(CVE-2015-8982)

  - The posix_spawn_file_actions_addopen function in glibc
    before 2.20 does not copy its path argument in
    accordance with the POSIX specification, which allows
    context-dependent attackers to trigger use-after-free
    vulnerabilities.(CVE-2014-4043)

  - res_query in libresolv in glibc before 2.25 allows
    remote attackers to cause a denial of service (NULL
    pointer dereference and process crash).(CVE-2015-5180)

  - A buffer overflow has been discovered in the GNU C
    Library (aka glibc or libc6) in the
    __mempcpy_avx512_no_vzeroupper function when particular
    conditions are met. An attacker could use this
    vulnerability to cause a denial of service or
    potentially execute code.(CVE-2018-11237)

  - In the GNU C Library (aka glibc or libc6) through 2.29,
    proceed_next_node in posix/regexec.c has a heap-based
    buffer over-read via an attempted case-insensitive
    regular-expression match.(CVE-2019-9169)

  - The iconv program in the GNU C Library (aka glibc or
    libc6) 2.25 and earlier, when invoked with the -c
    option, enters an infinite loop when processing invalid
    multi-byte input sequences, leading to a denial of
    service.(CVE-2016-10228)

  - The DNS stub resolver in the GNU C Library (aka glibc
    or libc6) before version 2.26, when EDNS support is
    enabled, will solicit large UDP responses from name
    servers, potentially simplifying off-path DNS spoofing
    attacks due to IP fragmentation.(CVE-2017-12132)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2030
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ebae79a");
  script_set_attribute(attribute:"solution", value:
"Update the affected glibc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9169");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nscd");
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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["glibc-2.17-196.h27",
        "glibc-common-2.17-196.h27",
        "glibc-devel-2.17-196.h27",
        "glibc-headers-2.17-196.h27",
        "glibc-static-2.17-196.h27",
        "glibc-utils-2.17-196.h27",
        "nscd-2.17-196.h27"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
