#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125285);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_name(english:"Virtuozzo 7 : bpftool / cpupools / cpupools-features / etc (VZA-2019-039)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the bpftool / cpupools /
cpupools-features / etc packages installed, the Virtuozzo
installation on the remote host is affected by the following
vulnerability :

  - The Microarchitectural Store Buffer Data (MDS) is a
    series of hardware vulnerabilities which allow
    speculative execution attacks on Intel processors. A
    malicious application or guest virtual machine can use
    this flaw to gain access to data stored in internal CPU
    buffers, bypassing security restrictions. For more
    details, visit the Virtuozzo Blog at
    https://www.virtuozzo.com/blog-review/details/blog/view
    /virtuozzo-guidance-on-the-microarchitectural-store-buf
    fer-data-mds-vulnerability.html.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://virtuozzosupport.force.com/s/article/VZA-2019-039");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/mds");
  # https://www.virtuozzo.com/blog-review/details/blog/view/virtuozzo-guidance-on-the-microarchitectural-store-buffer-data-mds-vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?355d0e23");
  script_set_attribute(attribute:"solution", value:
"Update the affected bpftool / cpupools / cpupools-features / etc package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:cpupools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:cpupools-features");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ksm-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-service-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prlctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-ploop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-img-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-common-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-tools-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-headers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["bpftool-3.10.0-957.12.2.vz7.86.2",
        "cpupools-7.0.19-1.vz7",
        "cpupools-features-7.0.19-1.vz7",
        "kernel-tools-3.10.0-957.12.2.vz7.86.2",
        "kernel-tools-libs-3.10.0-957.12.2.vz7.86.2",
        "kernel-tools-libs-devel-3.10.0-957.12.2.vz7.86.2",
        "ksm-vz-2.12.0-18.6.3.vz7.21.6",
        "libvirt-4.5.0-10.vz7.10.1",
        "libvirt-admin-4.5.0-10.vz7.10.1",
        "libvirt-bash-completion-4.5.0-10.vz7.10.1",
        "libvirt-client-4.5.0-10.vz7.10.1",
        "libvirt-daemon-4.5.0-10.vz7.10.1",
        "libvirt-daemon-config-network-4.5.0-10.vz7.10.1",
        "libvirt-daemon-config-nwfilter-4.5.0-10.vz7.10.1",
        "libvirt-daemon-driver-interface-4.5.0-10.vz7.10.1",
        "libvirt-daemon-driver-network-4.5.0-10.vz7.10.1",
        "libvirt-daemon-driver-nodedev-4.5.0-10.vz7.10.1",
        "libvirt-daemon-driver-nwfilter-4.5.0-10.vz7.10.1",
        "libvirt-daemon-driver-qemu-4.5.0-10.vz7.10.1",
        "libvirt-daemon-driver-storage-4.5.0-10.vz7.10.1",
        "libvirt-daemon-driver-storage-core-4.5.0-10.vz7.10.1",
        "libvirt-daemon-driver-vz-4.5.0-10.vz7.10.1",
        "libvirt-daemon-kvm-4.5.0-10.vz7.10.1",
        "libvirt-daemon-vz-4.5.0-10.vz7.10.1",
        "libvirt-devel-4.5.0-10.vz7.10.1",
        "libvirt-docs-4.5.0-10.vz7.10.1",
        "libvirt-libs-4.5.0-10.vz7.10.1",
        "libvirt-nss-4.5.0-10.vz7.10.1",
        "perf-3.10.0-957.12.2.vz7.86.2",
        "ploop-7.0.140.2-1.vz7",
        "ploop-devel-7.0.140.2-1.vz7",
        "ploop-lib-7.0.140.2-1.vz7",
        "prl-disp-legacy-7.0.942.2-1.vz7",
        "prl-disp-service-7.0.942.2-1.vz7",
        "prl-disp-service-tests-7.0.942.2-1.vz7",
        "prlctl-7.0.173.2-1.vz7",
        "python-perf-3.10.0-957.12.2.vz7.86.2",
        "python-ploop-7.0.140.2-1.vz7",
        "qemu-img-vz-2.12.0-18.6.3.vz7.21.6",
        "qemu-kvm-common-vz-2.12.0-18.6.3.vz7.21.6",
        "qemu-kvm-tools-vz-2.12.0-18.6.3.vz7.21.6",
        "qemu-kvm-vz-2.12.0-18.6.3.vz7.21.6",
        "vzkernel-3.10.0-957.12.2.vz7.86.2",
        "vzkernel-debug-3.10.0-957.12.2.vz7.86.2",
        "vzkernel-debug-devel-3.10.0-957.12.2.vz7.86.2",
        "vzkernel-devel-3.10.0-957.12.2.vz7.86.2",
        "vzkernel-doc-3.10.0-957.12.2.vz7.86.2",
        "vzkernel-headers-3.10.0-957.12.2.vz7.86.2"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / cpupools / cpupools-features / etc");
}
