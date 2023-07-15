#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110157);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/20");

  script_cve_id(
    "CVE-2018-1087",
    "CVE-2018-3639"
  );

  script_name(english:"Virtuozzo 6 : cpupools / cpupools-features / etc (VZA-2018-034)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the cpupools / cpupools-features / etc
packages installed, the Virtuozzo installation on the remote host is
affected by the following vulnerabilities :

  - A flaw was found in the way the Linux kernel's KVM
    hypervisor handled exceptions delivered after a stack
    switch operation via Mov SS or Pop SS instructions.
    During the stack switch operation, the processor did
    not deliver interrupts and exceptions, rather they are
    delivered once the first instruction after the stack
    switch is executed. An unprivileged KVM guest user
    could use this flaw to crash the guest or, potentially,
    escalate their privileges in the guest.

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of Load & Store instructions (a commonly used
    performance optimization). It relies on the presence of
    a precisely-defined instruction sequence in the
    privileged code as well as the fact that memory read
    from address to which a recent memory write has
    occurred may see an older value and subsequently cause
    an update into the microprocessor's data cache even for
    speculatively executed instructions that never actually
    commit (retire). As a result, an unprivileged attacker
    could use this flaw to read privileged memory by
    conducting targeted cache side-channel attacks.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2941425");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:1651");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-1087");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-3639");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/pop_ss");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/ssbd");
  script_set_attribute(attribute:"solution", value:
"Update the affected cpupools / cpupools-features / etc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:cpupools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:cpupools-features");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-reconfiguration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-bios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-bm-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-transporter-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-vi-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-vmm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-vncserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-vzvncserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-virtualization-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-virtualization-sdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-virtualization-sdk-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-parallels-virtualization-sdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

pkgs = ["cpupools-6.0.12-48",
        "cpupools-features-6.0.12-48",
        "parallels-kernel-modules-6.12.26079.1233231-1.el6",
        "parallels-reconfiguration-6.12.26079.1233231-1",
        "parallels-server-6.12.26079.1233231-1.el6",
        "parallels-server-bios-6.12.26079.1233231-1.el6",
        "parallels-server-bm-release-6.0.12-3707",
        "parallels-server-cli-6.12.26079.1233231-1.el6",
        "parallels-server-docs-6.12.26079.1233231-1.el6.el6",
        "parallels-server-efi-6.12.26079.1233231-1.el6",
        "parallels-server-lib-6.12.26079.1233231-1.el6",
        "parallels-server-transporter-agents-6.12.26079.1233231-1.el6",
        "parallels-server-vi-cli-6.12.26079.1233231-1.el6",
        "parallels-server-vmm-6.12.26079.1233231-1.el6",
        "parallels-server-vncserver-6.12.26079.1233231-1.el6",
        "parallels-server-vzvncserver-6.12.26079.1233231-1.el6",
        "parallels-virtualization-sdk-6.12.26079.1233231-1.el6",
        "parallels-virtualization-sdk-devel-6.12.26079.1233231-1.el6",
        "parallels-virtualization-sdk-docs-6.12.26079.1233231-1.el6",
        "parallels-web-6.12.26079.1233231-1",
        "python-parallels-virtualization-sdk-6.12.26079.1233231-1.el6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-6", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpupools / cpupools-features / etc");
}
