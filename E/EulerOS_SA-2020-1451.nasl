#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135613);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/30");

  script_cve_id(
    "CVE-2018-15686",
    "CVE-2018-16866",
    "CVE-2018-16888"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.2 : systemd (EulerOS-SA-2020-1451)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the systemd packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - It was discovered systemd does not correctly check the
    content of PIDFile files before using it to kill
    processes. When a service is run from an unprivileged
    user (e.g. User field set in the service file), a local
    attacker who is able to write to the PIDFile of the
    mentioned service may use this flaw to trick systemd
    into killing other services and/or privileged
    processes. Versions before v237 are
    vulnerable.(CVE-2018-16888)

  - An out of bounds read was discovered in
    systemd-journald in the way it parses log messages that
    terminate with a colon ':'. A local attacker can use
    this flaw to disclose process memory data. Versions
    from v221 to v239 are vulnerable.(CVE-2018-16866)

  - A vulnerability in unit_deserialize of systemd allows
    an attacker to supply arbitrary state across systemd
    re-execution via NotifyAccess. This can be used to
    improperly influence systemd execution and possibly
    lead to root privilege escalation. Affected releases
    are systemd versions up to and including
    239.(CVE-2018-15686)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1451
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9bb4f49e");
  script_set_attribute(attribute:"solution", value:
"Update the affected systemd packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15686");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-networkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-resolved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-udev-comat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libgudev1-219-62.5.h105",
        "systemd-219-62.5.h105",
        "systemd-devel-219-62.5.h105",
        "systemd-libs-219-62.5.h105",
        "systemd-networkd-219-62.5.h105",
        "systemd-python-219-62.5.h105",
        "systemd-resolved-219-62.5.h105",
        "systemd-sysv-219-62.5.h105",
        "systemd-udev-comat-219-62.5.h105"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd");
}
