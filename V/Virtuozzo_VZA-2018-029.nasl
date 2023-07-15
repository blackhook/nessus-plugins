#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109801);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2017-1000410",
    "CVE-2017-13166",
    "CVE-2017-17450",
    "CVE-2017-17807",
    "CVE-2017-5754",
    "CVE-2018-1130",
    "CVE-2018-5754",
    "CVE-2018-6927",
    "CVE-2018-8897"
  );
  script_xref(name:"IAVA", value:"2018-A-0019");

  script_name(english:"Virtuozzo 6 : parallels-server-bm-release / vzkernel / etc (VZA-2018-029)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the parallels-server-bm-release /
vzkernel / etc packages installed, the Virtuozzo installation on the
remote host is affected by the following vulnerabilities :

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of instructions (a commonly used performance
    optimization). There are three primary variants of the
    issue which differ in the way the speculative execution
    can be exploited. Variant CVE-2017-5754 relies on the
    fact that, on impacted microprocessors, during
    speculative execution of instruction permission faults,
    exception generation triggered by a faulting access is
    suppressed until the retirement of the whole
    instruction block. In a combination with the fact that
    memory accesses may populate the cache even when the
    block is being dropped and never committed (executed),
    an unprivileged local attacker could use this flaw to
    read privileged (kernel space) memory by conducting
    targeted cache side-channel attacks. NOTE: This update
    fixes the 32-bit compatibility layer on x86-64
    processors, i.e. when 32-bit containers are executed on
    64-bit processors.

  - A bug in the 32-bit compatibility layer of the ioctl
    handling code of the v4l2 video driver in the Linux
    kernel has been found. A memory protection mechanism
    ensuring that user-provided buffers always point to a
    userspace memory were disabled, allowing destination
    address to be in a kernel space. This flaw could be
    exploited by an attacker to overwrite a kernel memory
    from an unprivileged userspace process, leading to
    privilege escalation.

  - The KEYS subsystem in the Linux kernel omitted an
    access-control check when writing a key to the current
    task's default keyring, allowing a local user to bypass
    security checks to the keyring. This compromises the
    validity of the keyring for those who rely on it.

  - A flaw was found in the processing of incoming L2CAP
    bluetooth commands. Uninitialized stack variables can
    be sent to an attacker leaking data in kernel address
    space.

  - Linux kernel before version 4.16-rc7 is vulnerable to a
    null pointer dereference in dccp_write_xmit() function
    in net/dccp/output.c in that allows a local user to
    cause a denial of service by a number of certain
    crafted system calls.

  - A flaw was found in the way the Linux kernel handled
    exceptions delivered after a stack switch operation via
    Mov SS or Pop SS instructions. During the stack switch
    operation, the processor did not deliver interrupts and
    exceptions, rather they are delivered once the first
    instruction after the stack switch is executed. An
    unprivileged system user could use this flaw to crash
    the system kernel resulting in the denial of service.

  - net/netfilter/xt_osf.c in the Linux kernel through
    4.14.4 does not require the CAP_NET_ADMIN capability
    for add_callback and remove_callback operations. This
    allows local users to bypass intended access
    restrictions because the xt_osf_fingers data structure
    is shared across all network namespaces.

  - The futex_requeue function in kernel/futex.c in the
    Linux kernel, before 4.14.15, might allow attackers to
    cause a denial of service (integer overflow) or
    possibly have unspecified other impacts by triggering a
    negative wake or requeue value.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2939247");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:1319");
  script_set_attribute(attribute:"solution", value:
"Update the affected parallels-server-bm-release / vzkernel / etc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-bm-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzmodules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzmodules-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["parallels-server-bm-release-6.0.12-3703",
        "vzkernel-2.6.32-042stab129.1",
        "vzkernel-devel-2.6.32-042stab129.1",
        "vzkernel-firmware-2.6.32-042stab129.1",
        "vzmodules-2.6.32-042stab129.1",
        "vzmodules-devel-2.6.32-042stab129.1"];

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
