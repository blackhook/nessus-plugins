#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152281);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2020-25650",
    "CVE-2020-25651",
    "CVE-2020-25652",
    "CVE-2020-25653"
  );

  script_name(english:"EulerOS 2.0 SP9 : spice-vdagent (EulerOS-SA-2021-2283)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the spice-vdagent package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in the way the spice-vdagentd daemon
    handled file transfers from the host system to the
    virtual machine. Any unprivileged local guest user with
    access to the UNIX domain socket path
    `/run/spice-vdagentd/spice-vdagent-sock` could use this
    flaw to perform a memory denial of service for
    spice-vdagentd or even other processes in the VM
    system. The highest threat from this vulnerability is
    to system availability. This flaw affects spice-vdagent
    versions 0.20 and previous versions.(CVE-2020-25650)

  - A flaw was found in the SPICE file transfer protocol.
    File data from the host system can end up in full or in
    parts in the client connection of an illegitimate local
    user in the VM system. Active file transfers from other
    users could also be interrupted, resulting in a denial
    of service. The highest threat from this vulnerability
    is to data confidentiality as well as system
    availability. This flaw affects spice-vdagent versions
    0.20 and prior.(CVE-2020-25651)

  - A flaw was found in the spice-vdagentd daemon, where it
    did not properly handle client connections that can be
    established via the UNIX domain socket in
    `/run/spice-vdagentd/spice-vdagent-sock`. Any
    unprivileged local guest user could use this flaw to
    prevent legitimate agents from connecting to the
    spice-vdagentd daemon, resulting in a denial of
    service. The highest threat from this vulnerability is
    to system availability. This flaw affects spice-vdagent
    versions 0.20 and prior.(CVE-2020-25652)

  - A race condition vulnerability was found in the way the
    spice-vdagentd daemon handled new client connections.
    This flaw may allow an unprivileged local guest user to
    become the active agent for spice-vdagentd, possibly
    resulting in a denial of service or information leakage
    from the host. The highest threat from this
    vulnerability is to data confidentiality as well as
    system availability. This flaw affects spice-vdagent
    versions 0.20 and prior.(CVE-2020-25653)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2283
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf7124cd");
  script_set_attribute(attribute:"solution", value:
"Update the affected spice-vdagent packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25653");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-25651");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:spice-vdagent-help");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["spice-vdagent-help-0.18.0-4.h1.eulerosv2r9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spice-vdagent");
}
