#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123701);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_cve_id("CVE-2018-15688", "CVE-2018-16864", "CVE-2018-16865");

  script_name(english:"EulerOS Virtualization 2.5.4 : systemd (EulerOS-SA-2019-1233)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the systemd packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - An allocation of memory without limits, that could
    result in the stack clashing with another memory
    region, was discovered in systemd-journald when many
    entries are sent to the journal socket. A local
    attacker, or a remote one if systemd-journal-remote is
    used, may use this flaw to crash systemd-journald or
    execute code with journald
    privileges.i1/4^CVE-2018-16865i1/4%0

  - It was discovered that systemd-network does not
    correctly keep track of a buffer size when constructing
    DHCPv6 packets. This flaw may lead to an integer
    underflow that can be used to produce an heap-based
    buffer overflow. A malicious host on the same network
    segment as the victim's one may advertise itself as a
    DHCPv6 server and exploit this flaw to cause a Denial
    of Service or potentially gain code execution on the
    victim's machine.i1/4^CVE-2018-15688i1/4%0

  - An allocation of memory without limits, that could
    result in the stack clashing with another memory
    region, was discovered in systemd-journald when a
    program with long command line arguments calls syslog.
    A local attacker may use this flaw to crash
    systemd-journald or escalate
    privileges.i1/4^CVE-2018-16864i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1233
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1c52856");
  script_set_attribute(attribute:"solution", value:
"Update the affected systemd packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15688");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgudev1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-networkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-resolved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.5.4");
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
if (uvp != "2.5.4") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.5.4");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libgudev1-devel-219-57.h68",
        "systemd-219-57.h68",
        "systemd-devel-219-57.h68",
        "systemd-libs-219-57.h68",
        "systemd-networkd-219-57.h68",
        "systemd-python-219-57.h68",
        "systemd-resolved-219-57.h68",
        "systemd-sysv-219-57.h68"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd");
}
