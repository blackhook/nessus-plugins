#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131368);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-17041",
    "CVE-2019-17042"
  );

  script_name(english:"EulerOS 2.0 SP8 : rsyslog (EulerOS-SA-2019-2302)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the rsyslog packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in Rsyslog v8.1908.0.
    contrib/pmaixforwardedfrom/pmaixforwardedfrom.c has a
    heap overflow in the parser for AIX log messages. The
    parser tries to locate a log message delimiter (in this
    case, a space or a colon) but fails to account for
    strings that do not satisfy this constraint. If the
    string does not match, then the variable lenMsg will
    reach the value zero and will skip the sanity check
    that detects invalid log messages. The message will
    then be considered valid, and the parser will eat up
    the nonexistent colon delimiter. In doing so, it will
    decrement lenMsg, a signed integer, whose value was
    zero and now becomes minus one. The following step in
    the parser is to shift left the contents of the
    message. To do this, it will call memmove with the
    right pointers to the target and destination strings,
    but the lenMsg will now be interpreted as a huge value,
    causing a heap overflow.(CVE-2019-17041)

  - An issue was discovered in Rsyslog v8.1908.0.
    contrib/pmcisconames/pmcisconames.c has a heap overflow
    in the parser for Cisco log messages. The parser tries
    to locate a log message delimiter (in this case, a
    space or a colon), but fails to account for strings
    that do not satisfy this constraint. If the string does
    not match, then the variable lenMsg will reach the
    value zero and will skip the sanity check that detects
    invalid log messages. The message will then be
    considered valid, and the parser will eat up the
    nonexistent colon delimiter. In doing so, it will
    decrement lenMsg, a signed integer, whose value was
    zero and now becomes minus one. The following step in
    the parser is to shift left the contents of the
    message. To do this, it will call memmove with the
    right pointers to the target and destination strings,
    but the lenMsg will now be interpreted as a huge value,
    causing a heap overflow.(CVE-2019-17042)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2302
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38439ac6");
  script_set_attribute(attribute:"solution", value:
"Update the affected rsyslog packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rsyslog-mmjsonparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rsyslog-relp");
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

pkgs = ["rsyslog-8.37.0-2.h18.eulerosv2r8",
        "rsyslog-gnutls-8.37.0-2.h18.eulerosv2r8",
        "rsyslog-gssapi-8.37.0-2.h18.eulerosv2r8",
        "rsyslog-mmjsonparse-8.37.0-2.h18.eulerosv2r8",
        "rsyslog-mysql-8.37.0-2.h18.eulerosv2r8",
        "rsyslog-relp-8.37.0-2.h18.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsyslog");
}
