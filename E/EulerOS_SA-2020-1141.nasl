#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133975);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-6467",
    "CVE-2019-6477"
  );

  script_name(english:"EulerOS 2.0 SP8 : bind (EulerOS-SA-2020-1141)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the bind packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - With pipelining enabled each incoming query on a TCP
    connection requires a similar resource allocation to a
    query received via UDP or via TCP without pipelining
    enabled. A client using a TCP-pipelined connection to a
    server could consume more resources than the server has
    been provisioned to handle. When a TCP connection with
    a large number of pipelined queries is closed, the load
    on the server releasing these multiple resources can
    cause it to become unresponsive, even for queries that
    can be answered authoritatively or from cache. (This is
    most likely to be perceived as an intermittent server
    problem).(CVE-2019-6477)

  - A programming error in the nxdomain-redirect feature
    can cause an assertion failure in query.c if the
    alternate namespace used by nxdomain-redirect is a
    descendant of a zone that is served locally. The most
    likely scenario where this might occur is if the
    server, in addition to performing NXDOMAIN redirection
    for recursive clients, is also serving a local copy of
    the root zone or using mirroring to provide the root
    zone, although other configurations are also possible.
    Versions affected: BIND 9.12.0-> 9.12.4, 9.14.0. Also
    affects all releases in the 9.13 development
    branch.(CVE-2019-6467)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1141
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b140587a");
  script_set_attribute(attribute:"solution", value:
"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-bind");
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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["bind-9.11.4-10.P2.h19.eulerosv2r8",
        "bind-chroot-9.11.4-10.P2.h19.eulerosv2r8",
        "bind-export-devel-9.11.4-10.P2.h19.eulerosv2r8",
        "bind-export-libs-9.11.4-10.P2.h19.eulerosv2r8",
        "bind-libs-9.11.4-10.P2.h19.eulerosv2r8",
        "bind-libs-lite-9.11.4-10.P2.h19.eulerosv2r8",
        "bind-license-9.11.4-10.P2.h19.eulerosv2r8",
        "bind-pkcs11-9.11.4-10.P2.h19.eulerosv2r8",
        "bind-pkcs11-libs-9.11.4-10.P2.h19.eulerosv2r8",
        "bind-pkcs11-utils-9.11.4-10.P2.h19.eulerosv2r8",
        "bind-utils-9.11.4-10.P2.h19.eulerosv2r8",
        "python3-bind-9.11.4-10.P2.h19.eulerosv2r8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
