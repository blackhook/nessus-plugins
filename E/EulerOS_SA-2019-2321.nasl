#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131486);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-5738",
    "CVE-2018-5745",
    "CVE-2019-6465"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.3.0 : bind (EulerOS-SA-2019-2321)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the bind packages installed, the EulerOS
Virtualization for ARM 64 installation on the remote host is affected
by the following vulnerabilities :

  - Change #4777 (introduced in October 2017) introduced an
    unforeseen issue in releases which were issued after
    that date, affecting which clients are permitted to
    make recursive queries to a BIND nameserver. The
    intended (and documented) behavior is that if an
    operator has not specified a value for the
    'allow-recursion' setting, it SHOULD default to one of
    the following: none, if 'recursion no' is set in
    named.conf a value inherited from the
    'allow-query-cache' or 'allow-query' settings IF
    'recursion yes' (the default for that setting) AND
    match lists are explicitly set for 'allow-query-cache'
    or 'allow-query' (see the BIND9 Administrative
    Reference Manual section 6.2 for more details) or the
    intended default of 'allow-recursion {localhost
    localnets}' if 'recursion yes' is in effect and no
    values are explicitly set for 'allow-query-cache' or
    'allow-query'. However, because of the regression
    introduced by change #4777, it is possible when
    'recursion yes' is in effect and no match list values
    are provided for 'allow-query-cache' or 'allow-query'
    for the setting of 'allow-recursion' to inherit a
    setting of all hosts from the 'allow-query' setting
    default, improperly permitting recursion to all
    clients. Affects BIND 9.9.12, 9.10.7, 9.11.3,
    9.12.0->9.12.1-P2, the development release 9.13.0, and
    also releases 9.9.12-S1, 9.10.7-S1, 9.11.3-S1, and
    9.11.3-S2 from BIND 9 Supported Preview
    Edition.(CVE-2018-5738)

  - Controls for zone transfers may not be properly applied
    to Dynamically Loadable Zones (DLZs) if the zones are
    writable Versions affected: BIND 9.9.0 -> 9.10.8-P1,
    9.11.0 -> 9.11.5-P2, 9.12.0 -> 9.12.3-P2, and versions
    9.9.3-S1 -> 9.11.5-S3 of BIND 9 Supported Preview
    Edition. Versions 9.13.0 -> 9.13.6 of the 9.13
    development branch are also affected. Versions prior to
    BIND 9.9.0 have not been evaluated for vulnerability to
    CVE-2019-6465.(CVE-2019-6465)

  - 'managed-keys' is a feature which allows a BIND
    resolver to automatically maintain the keys used by
    trust anchors which operators configure for use in
    DNSSEC validation. Due to an error in the managed-keys
    feature it is possible for a BIND server which uses
    managed-keys to exit due to an assertion failure if,
    during key rollover, a trust anchor's keys are replaced
    with keys which use an unsupported algorithm. Versions
    affected: BIND 9.9.0 -> 9.10.8-P1, 9.11.0 -> 9.11.5-P1,
    9.12.0 -> 9.12.3-P1, and versions 9.9.3-S1 -> 9.11.5-S3
    of BIND 9 Supported Preview Edition. Versions 9.13.0 ->
    9.13.6 of the 9.13 development branch are also
    affected. Versions prior to BIND 9.9.0 have not been
    evaluated for vulnerability to
    CVE-2018-5745.(CVE-2018-5745)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2321
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3f1b816");
  script_set_attribute(attribute:"solution", value:
"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.3.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.3.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.3.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["bind-export-libs-9.11.4-10.P2.h12.eulerosv2r8",
        "bind-libs-9.11.4-10.P2.h12.eulerosv2r8",
        "bind-libs-lite-9.11.4-10.P2.h12.eulerosv2r8",
        "bind-license-9.11.4-10.P2.h12.eulerosv2r8",
        "bind-utils-9.11.4-10.P2.h12.eulerosv2r8",
        "python3-bind-9.11.4-10.P2.h12.eulerosv2r8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
