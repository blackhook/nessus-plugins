#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102922);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2017-1000111",
    "CVE-2017-1000112",
    "CVE-2017-10661",
    "CVE-2017-11176",
    "CVE-2017-14106",
    "CVE-2017-7541",
    "CVE-2017-7542"
  );

  script_name(english:"Virtuozzo 6 : parallels-server-bm-release / vzkernel / etc (VZA-2017-076)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the parallels-server-bm-release /
vzkernel / etc packages installed, the Virtuozzo installation on the
remote host is affected by the following vulnerabilities :

  - An integer overflow vulnerability in
    ip6_find_1stfragopt() function was found. A local
    attacker that has privileges (of CAP_NET_RAW) to open
    raw socket can cause an infinite loop inside the
    ip6_find_1stfragopt() function.

  - Race condition in fs/timerfd.c in the Linux kernel
    before 4.10.15 allows local users to gain privileges or
    cause a denial of service (list corruption or
    use-after-free) via simultaneous file-descriptor
    operations that leverage improper might_cancel
    queueing.

  - A race condition issue leading to a use-after-free flaw
    was found in the way the raw packet sockets are
    implemented in the Linux kernel networking subsystem
    handling synchronization. A local user able to open a
    raw packet socket (requires the CAP_NET_RAW capability)
    could use this flaw to elevate their privileges on the
    system.

  - Andrey Konovalov discovered a race condition in the UDP
    Fragmentation Offload (UFO) code in the Linux kernel. A
    local attacker could use this to cause a denial of
    service or execute arbitrary code.

  - Kernel memory corruption due to a buffer overflow was
    found in brcmf_cfg80211_mgmt_tx() function in Linux
    kernels from v3.9-rc1 to v4.13-rc1. The vulnerability
    can be triggered by sending a crafted NL80211_CMD_FRAME
    packet via netlink. This flaw is unlikely to be
    triggered remotely as certain userspace code is needed
    for this. An unprivileged local user could use this
    flaw to induce kernel memory corruption on the system,
    leading to a crash. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.

  - The mq_notify function in the Linux kernel through
    4.11.9 does not set the sock pointer to NULL upon entry
    into the retry logic. During a user-space close of a
    Netlink socket, it allows attackers to possibly cause a
    situation where a value may be used after being freed
    (use after free) which may lead to memory corruption or
    other unspecified other impact.

  - The tcp_disconnect function in net/ipv4/tcp.c in the
    Linux kernel before 4.12 allows local users to cause a
    denial of service (__tcp_select_window divide-by-zero
    error and system crash) by triggering a disconnect
    within a certain tcp_recvmsg code path.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2869792");
  script_set_attribute(attribute:"see_also", value:"https://rhn.redhat.com/errata/RHBA-2017-2504.html");
  script_set_attribute(attribute:"see_also", value:"https://rhn.redhat.com/errata/RHSA-2017-0892.html");
  script_set_attribute(attribute:"see_also", value:"https://rhn.redhat.com/errata/RHSA-2017-1372.html");
  script_set_attribute(attribute:"see_also", value:"https://rhn.redhat.com/errata/RHSA-2017-1486.html");
  script_set_attribute(attribute:"see_also", value:"https://rhn.redhat.com/errata/RHSA-2017-1723.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected parallels-server-bm-release / vzkernel / etc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-bm-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzmodules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzmodules-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 6.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["parallels-server-bm-release-6.0.12-3683",
        "vzkernel-2.6.32-042stab124.2",
        "vzkernel-devel-2.6.32-042stab124.2",
        "vzkernel-firmware-2.6.32-042stab124.2",
        "vzmodules-2.6.32-042stab124.2",
        "vzmodules-devel-2.6.32-042stab124.2"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-6", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "parallels-server-bm-release / vzkernel / etc");
}
