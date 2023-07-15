#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110234);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2018-1087",
    "CVE-2018-3639",
    "CVE-2018-8897"
  );

  script_name(english:"Virtuozzo 7 : anaconda / anaconda-core / anaconda-dracut / etc (VZA-2018-037)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the anaconda / anaconda-core /
anaconda-dracut / etc packages installed, the Virtuozzo installation
on the remote host is affected by the following vulnerabilities :

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
    conducting targeted cache side-channel attacks. NOTE:
    This fix also requires CPU microcode/firmware updates
    and subscribers are advised to contact their hardware
    OEM vendors to receive the appropriate
    microcode/firmware for their processor. A kernel
    update, without the appropriate firmware/microcode
    updated for the processor, is insufficient to remediate
    this vulnerability.

  - A flaw was found in the way the Linux kernel handled
    exceptions delivered after a stack switch operation via
    Mov SS or Pop SS instructions. During the stack switch
    operation, the processor did not deliver interrupts and
    exceptions, rather they are delivered once the first
    instruction after the stack switch is executed. An
    unprivileged system user could use this flaw to crash
    the system kernel resulting in the denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2941807");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:1651");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-1087");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-3639");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-8897");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/pop_ss");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/ssbd");
  script_set_attribute(attribute:"solution", value:
"Update the affected anaconda / anaconda-core / anaconda-dracut / etc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-dracut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-widgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-widgets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:cpupools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:cpupools-features");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kpatch-kmod-48.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ksm-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzctl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-service-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prlctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-img-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-common-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-tools-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-headers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["anaconda-21.48.22.121-3.vz7.58.4",
        "anaconda-core-21.48.22.121-3.vz7.58.4",
        "anaconda-dracut-21.48.22.121-3.vz7.58.4",
        "anaconda-gui-21.48.22.121-3.vz7.58.4",
        "anaconda-tui-21.48.22.121-3.vz7.58.4",
        "anaconda-widgets-21.48.22.121-3.vz7.58.4",
        "anaconda-widgets-devel-21.48.22.121-3.vz7.58.4",
        "cpupools-7.0.15-0.vz7.1",
        "cpupools-features-7.0.15-0.vz7.1",
        "kpatch-kmod-48.1-0.5.0-1.vl7",
        "ksm-vz-2.9.0-16.13.vz7.76.5",
        "libvirt-3.6.0-1.vz7.32.2",
        "libvirt-admin-3.6.0-1.vz7.32.2",
        "libvirt-client-3.6.0-1.vz7.32.2",
        "libvirt-daemon-3.6.0-1.vz7.32.2",
        "libvirt-daemon-config-network-3.6.0-1.vz7.32.2",
        "libvirt-daemon-config-nwfilter-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-interface-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-lxc-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-network-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-nodedev-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-nwfilter-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-qemu-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-secret-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-storage-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-storage-core-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-storage-disk-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-storage-gluster-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-storage-iscsi-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-storage-logical-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-storage-mpath-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-storage-rbd-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-storage-scsi-3.6.0-1.vz7.32.2",
        "libvirt-daemon-driver-vz-3.6.0-1.vz7.32.2",
        "libvirt-daemon-kvm-3.6.0-1.vz7.32.2",
        "libvirt-daemon-lxc-3.6.0-1.vz7.32.2",
        "libvirt-daemon-vz-3.6.0-1.vz7.32.2",
        "libvirt-devel-3.6.0-1.vz7.32.2",
        "libvirt-docs-3.6.0-1.vz7.32.2",
        "libvirt-libs-3.6.0-1.vz7.32.2",
        "libvirt-lock-sanlock-3.6.0-1.vz7.32.2",
        "libvirt-login-shell-3.6.0-1.vz7.32.2",
        "libvirt-nss-3.6.0-1.vz7.32.2",
        "libvzctl-7.0.470.4-1.vz7",
        "libvzctl-devel-7.0.470.4-1.vz7",
        "prl-disp-legacy-7.0.820.9-1.vz7",
        "prl-disp-service-7.0.820.9-1.vz7",
        "prl-disp-service-tests-7.0.820.9-1.vz7",
        "prlctl-7.0.148.1-1.vz7",
        "qemu-img-vz-2.9.0-16.13.vz7.76.5",
        "qemu-kvm-common-vz-2.9.0-16.13.vz7.76.5",
        "qemu-kvm-tools-vz-2.9.0-16.13.vz7.76.5",
        "qemu-kvm-vz-2.9.0-16.13.vz7.76.5",
        "vzkernel-3.10.0-693.21.1.vz7.48.2",
        "vzkernel-debug-3.10.0-693.21.1.vz7.48.2",
        "vzkernel-debug-devel-3.10.0-693.21.1.vz7.48.2",
        "vzkernel-devel-3.10.0-693.21.1.vz7.48.2",
        "vzkernel-headers-3.10.0-693.21.1.vz7.48.2"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "anaconda / anaconda-core / anaconda-dracut / etc");
}
