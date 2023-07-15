#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105657);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2017-5715",
    "CVE-2017-5753",
    "CVE-2017-5754"
  );
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"Virtuozzo 7 : crit / criu / criu-devel / ksm-vz / libcompel / etc (VZA-2018-003)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the crit / criu / criu-devel / ksm-vz /
libcompel / etc packages installed, the Virtuozzo installation on the
remote host is affected by the following vulnerabilities :

  - CVE-2017-5715 triggers the speculative execution by
    utilizing branch target injection. It relies on the
    presence of a precisely-defined instruction sequence in
    the privileged code as well as the fact that memory
    accesses may cause allocation into the microprocessor's
    data cache even for speculatively executed instructions
    that never actually commit (retire). As a result, an
    unprivileged attacker could use this flaw to cross the
    syscall and guest/host boundaries and read privileged
    memory by conducting targeted cache side-channel
    attacks.

  - CVE-2017-5753 triggers the speculative execution by
    performing a bounds-check bypass. It relies on the
    presence of a precisely-defined instruction sequence in
    the privileged code as well as the fact that memory
    accesses may cause allocation into the microprocessor's
    data cache even for speculatively executed instructions
    that never actually commit (retire). As a result, an
    unprivileged attacker could use this flaw to cross the
    syscall boundary and read privileged memory by
    conducting targeted cache side-channel attacks.

  - CVE-2017-5754 relies on the fact that, on impacted
    microprocessors, during speculative execution of
    instruction permission faults, exception generation
    triggered by a faulting access is suppressed until the
    retirement of the whole instruction block. In a
    combination with the fact that memory accesses may
    populate the cache even when the block is being dropped
    and never committed (executed), an unprivileged local
    attacker could use this flaw to read privileged (kernel
    space) memory by conducting targeted cache side-channel
    attacks.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2914297");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:0007");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:0023");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:0029");
  script_set_attribute(attribute:"solution", value:
"Update the affected crit / criu / criu-devel / ksm-vz / libcompel / etc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:criu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ksm-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libcompel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libcompel-devel");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-img-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-common-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-tools-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-guest-tools-win");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-headers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["crit-3.4.0.25.51-1.vz7",
        "criu-3.4.0.25.51-1.vz7",
        "criu-devel-3.4.0.25.51-1.vz7",
        "ksm-vz-2.9.0-16.3.vz7.36.3",
        "libcompel-3.4.0.25.51-1.vz7",
        "libcompel-devel-3.4.0.25.51-1.vz7",
        "libvirt-3.6.0-1.vz7.17.2",
        "libvirt-admin-3.6.0-1.vz7.17.2",
        "libvirt-client-3.6.0-1.vz7.17.2",
        "libvirt-daemon-3.6.0-1.vz7.17.2",
        "libvirt-daemon-config-network-3.6.0-1.vz7.17.2",
        "libvirt-daemon-config-nwfilter-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-interface-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-lxc-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-network-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-nodedev-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-nwfilter-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-qemu-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-secret-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-storage-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-storage-core-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-storage-disk-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-storage-gluster-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-storage-iscsi-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-storage-logical-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-storage-mpath-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-storage-rbd-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-storage-scsi-3.6.0-1.vz7.17.2",
        "libvirt-daemon-driver-vz-3.6.0-1.vz7.17.2",
        "libvirt-daemon-kvm-3.6.0-1.vz7.17.2",
        "libvirt-daemon-lxc-3.6.0-1.vz7.17.2",
        "libvirt-daemon-vz-3.6.0-1.vz7.17.2",
        "libvirt-devel-3.6.0-1.vz7.17.2",
        "libvirt-docs-3.6.0-1.vz7.17.2",
        "libvirt-libs-3.6.0-1.vz7.17.2",
        "libvirt-lock-sanlock-3.6.0-1.vz7.17.2",
        "libvirt-login-shell-3.6.0-1.vz7.17.2",
        "libvirt-nss-3.6.0-1.vz7.17.2",
        "libvzctl-7.0.442.9-1.vz7",
        "libvzctl-devel-7.0.442.9-1.vz7",
        "python-criu-3.4.0.25.51-1.vz7",
        "qemu-img-vz-2.9.0-16.3.vz7.36.3",
        "qemu-kvm-common-vz-2.9.0-16.3.vz7.36.3",
        "qemu-kvm-tools-vz-2.9.0-16.3.vz7.36.3",
        "qemu-kvm-vz-2.9.0-16.3.vz7.36.3",
        "vz-guest-tools-win-7.6-9.vz7",
        "vzkernel-3.10.0-693.11.6.vz7.40.4",
        "vzkernel-debug-3.10.0-693.11.6.vz7.40.4",
        "vzkernel-debug-devel-3.10.0-693.11.6.vz7.40.4",
        "vzkernel-devel-3.10.0-693.11.6.vz7.40.4",
        "vzkernel-headers-3.10.0-693.11.6.vz7.40.4"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "crit / criu / criu-devel / ksm-vz / libcompel / etc");
}
