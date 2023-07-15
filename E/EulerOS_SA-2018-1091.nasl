#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109489);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-10070",
    "CVE-2014-10071",
    "CVE-2017-18205",
    "CVE-2017-18206",
    "CVE-2018-7549"
  );

  script_name(english:"EulerOS 2.0 SP2 : zsh (EulerOS-SA-2018-1091)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the zsh package installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - The zsh shell is a command interpreter usable as an
    interactive login shell and as a shell script command
    processor. Zsh resembles the ksh shell (the Korn
    shell), but includes many enhancements. Zsh supports
    command line editing, built-in spelling correction,
    programmable command completion, shell functions (with
    autoloading), a history mechanism, and more.

  - Security fix(es):

  - In builtin.c in zsh before 5.4, when sh compatibility
    mode is used, there is a NULL pointer dereference
    during processing of the cd command with no argument if
    HOME is not set.(CVE-2017-18205)

  - zsh before 5.0.7 allows evaluation of the initial
    values of integer variables imported from the
    environment (instead of treating them as literal
    numbers). That could allow local privilege escalation,
    under some specific and atypical conditions where zsh
    is being invoked in privilege-elevation contexts when
    the environment has not been properly sanitized, such
    as when zsh is invoked by sudo on systems where
    'env_reset' has been disabled.(CVE-2014-10070)

  - In exec.c in zsh before 5.0.7, there is a buffer
    overflow for very long fds in the 'i1/4zi1/4+ fd'
    syntax.(CVE-2014-10071)

  - A buffer overflow flaw was found in the zsh shell
    symbolic link resolver. A local, unprivileged user can
    create a specially crafted directory path which leads
    to a buffer overflow in the context of the user trying
    to do a symbolic link resolution in the aforementioned
    path. If the user affected is privileged, this leads to
    privilege escalation.(CVE-2017-18206)

  - In params.c in zsh through 5.4.2, there is a crash
    during a copy of an empty hash table, as demonstrated
    by typeset -p.(CVE-2018-7549)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1091
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a73d4f52");
  script_set_attribute(attribute:"solution", value:
"Update the affected zsh packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:zsh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["zsh-5.0.2-7.h5"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zsh");
}
