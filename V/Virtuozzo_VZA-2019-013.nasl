#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122611);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/23");

  script_cve_id("CVE-2018-14634", "CVE-2018-14646", "CVE-2018-18559");

  script_name(english:"Virtuozzo 7 : OVMF / anaconda / anaconda-core / anaconda-dracut / etc (VZA-2019-013)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the OVMF / anaconda / anaconda-core /
anaconda-dracut / etc packages installed, the Virtuozzo installation
on the remote host is affected by the following vulnerabilities :

  - An integer overflow flaw was found in
    create_elf_tables(). An unprivileged local user with
    access to SUID (or otherwise privileged) binary could
    use this flaw to escalate their privileges on the
    system.

  - It was discovered that a race condition between
    packet_do_bind() and packet_notifier() in the
    implementation of AF_PACKET could lead to
    use-after-free. An unprivileged user on the host or in
    a container could exploit this to crash the kernel or,
    potentially, to escalate their privileges in the
    system.

  - The Linux kernel was found to be vulnerable to a NULL
    pointer dereference bug in the __netlink_ns_capable()
    function in the net/netlink/af_netlink.c file. A local
    attacker could exploit this when a net namespace with a
    netnsid is assigned to cause a kernel panic and a
    denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://virtuozzosupport.force.com/s/article/VZA-2019-013");
  script_set_attribute(attribute:"solution", value:
"Update the affected OVMF / anaconda / anaconda-core / anaconda-dracut / etc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14634");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-18559");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:OVMF");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-dracut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-widgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-widgets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:archive3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:centos-7-x86_64-ez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:cpupools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:cpupools-features");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:criu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:disp-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:eula-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:grubby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kpatch-kmod-73.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ksm-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libcompel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libcompel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-appliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-benchmarking");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-gobject-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-inspect-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libpcs_nbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libpcs_nbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlcommon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlxmlmodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlxmlmodel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreport-plugin-problem-report");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-vzct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-vzct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzctl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzlic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzlic-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:license-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:phaul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop-backup-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-service-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prlctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-blivet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-ploop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-subprocess32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-img-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-common-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-tools-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qt-assistant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qt-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qt-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qt-devel-private");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qt-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qt-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qt-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qt-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qt-qdbusviewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qt-qvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qt-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:readykernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:readykernel-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:rmond");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:shaman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:sles-15-x86_64-ez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vautomator-ui-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vcmmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vcmmd-policies");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virt-p2v-maker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virt-v2v");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virtuozzo-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-chunk-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-core-golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-core-golang-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-firewall-cfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-libs-shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-metadata-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ostor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ostor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ostor-nfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-guest-tools-lin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-guest-tools-updater");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-guest-tools-win");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzlicutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzmigrate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzreport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzstat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vztt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vztt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vztt-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vztt_checker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:yum-plugin-scst");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["OVMF-20171011-4.git92d07e48907f.vz7.8",
        "anaconda-21.48.22.134-3.vz7.47",
        "anaconda-core-21.48.22.134-3.vz7.47",
        "anaconda-dracut-21.48.22.134-3.vz7.47",
        "anaconda-gui-21.48.22.134-3.vz7.47",
        "anaconda-tui-21.48.22.134-3.vz7.47",
        "anaconda-widgets-21.48.22.134-3.vz7.47",
        "anaconda-widgets-devel-21.48.22.134-3.vz7.47",
        "archive3-1.4.43-1.vz7",
        "centos-7-x86_64-ez-7.0.0-25.vz7",
        "cpupools-7.0.18-1.vz7",
        "cpupools-features-7.0.18-1.vz7",
        "crit-3.10.0.23-1.vz7",
        "criu-3.10.0.23-1.vz7",
        "criu-devel-3.10.0.23-1.vz7",
        "disp-helper-0.0.167-1.vz7",
        "eula-anaconda-addon-0.6-2.vz7",
        "grubby-8.28-23.vz7.1",
        "kpatch-kmod-73.24-0.5.0-1.vl7",
        "ksm-vz-2.10.0-21.7.vz7.67",
        "libcompel-3.10.0.23-1.vz7",
        "libcompel-devel-3.10.0.23-1.vz7",
        "libguestfs-1.36.10-6.2.vz7.12",
        "libguestfs-appliance-1.36.10-6.2.vz7.12",
        "libguestfs-bash-completion-1.36.10-6.2.vz7.12",
        "libguestfs-benchmarking-1.36.10-6.2.vz7.12",
        "libguestfs-devel-1.36.10-6.2.vz7.12",
        "libguestfs-gobject-1.36.10-6.2.vz7.12",
        "libguestfs-gobject-devel-1.36.10-6.2.vz7.12",
        "libguestfs-gobject-doc-1.36.10-6.2.vz7.12",
        "libguestfs-inspect-icons-1.36.10-6.2.vz7.12",
        "libguestfs-java-1.36.10-6.2.vz7.12",
        "libguestfs-java-devel-1.36.10-6.2.vz7.12",
        "libguestfs-javadoc-1.36.10-6.2.vz7.12",
        "libguestfs-man-pages-ja-1.36.10-6.2.vz7.12",
        "libguestfs-man-pages-uk-1.36.10-6.2.vz7.12",
        "libguestfs-tools-1.36.10-6.2.vz7.12",
        "libguestfs-tools-c-1.36.10-6.2.vz7.12",
        "libpcs_nbd-1.0.7-1.vz7",
        "libpcs_nbd-devel-1.0.7-1.vz7",
        "libprlcommon-7.0.162-1.vz7",
        "libprlcommon-devel-7.0.162-1.vz7",
        "libprlsdk-7.0.226-2.vz7",
        "libprlsdk-devel-7.0.226-2.vz7",
        "libprlsdk-headers-7.0.226-2.vz7",
        "libprlsdk-python-7.0.226-2.vz7",
        "libprlxmlmodel-7.0.80-1.vz7",
        "libprlxmlmodel-devel-7.0.80-1.vz7",
        "libreport-plugin-problem-report-1.0.56-1.vz7",
        "libvirt-3.9.0-14.vz7.38",
        "libvirt-admin-3.9.0-14.vz7.38",
        "libvirt-client-3.9.0-14.vz7.38",
        "libvirt-daemon-3.9.0-14.vz7.38",
        "libvirt-daemon-config-nwfilter-3.9.0-14.vz7.38",
        "libvirt-daemon-driver-interface-3.9.0-14.vz7.38",
        "libvirt-daemon-driver-network-3.9.0-14.vz7.38",
        "libvirt-daemon-driver-nodedev-3.9.0-14.vz7.38",
        "libvirt-daemon-driver-nwfilter-3.9.0-14.vz7.38",
        "libvirt-daemon-driver-qemu-3.9.0-14.vz7.38",
        "libvirt-daemon-driver-storage-3.9.0-14.vz7.38",
        "libvirt-daemon-driver-storage-core-3.9.0-14.vz7.38",
        "libvirt-daemon-driver-vz-3.9.0-14.vz7.38",
        "libvirt-daemon-driver-vzct-3.9.0-14.vz7.38",
        "libvirt-daemon-kvm-3.9.0-14.vz7.38",
        "libvirt-daemon-vz-3.9.0-14.vz7.38",
        "libvirt-daemon-vzct-3.9.0-14.vz7.38",
        "libvirt-devel-3.9.0-14.vz7.38",
        "libvirt-docs-3.9.0-14.vz7.38",
        "libvirt-libs-3.9.0-14.vz7.38",
        "libvirt-nss-3.9.0-14.vz7.38",
        "libvzctl-7.0.506-1.vz7",
        "libvzctl-devel-7.0.506-1.vz7",
        "libvzlic-7.0.50-1.vz7",
        "libvzlic-devel-7.0.50-1.vz7",
        "license-anaconda-addon-0.12-2.vz7",
        "lua-guestfs-1.36.10-6.2.vz7.12",
        "ocaml-libguestfs-1.36.10-6.2.vz7.12",
        "ocaml-libguestfs-devel-1.36.10-6.2.vz7.12",
        "perl-Sys-Guestfs-1.36.10-6.2.vz7.12",
        "phaul-0.1.67-1.vz7",
        "ploop-7.0.137-1.vz7",
        "ploop-backup-7.0.28-1.vz7",
        "ploop-backup-devel-7.0.28-1.vz7",
        "ploop-devel-7.0.137-1.vz7",
        "ploop-lib-7.0.137-1.vz7",
        "prl-disp-backup-7.0.46-1.vz7",
        "prl-disp-legacy-7.0.926.1-1.vz7",
        "prl-disp-service-7.0.926.1-1.vz7",
        "prl-disp-service-tests-7.0.926.1-1.vz7",
        "prlctl-7.0.164-1.vz7",
        "python-blivet-0.61.15.69-1.vz7.3",
        "python-criu-3.10.0.23-1.vz7",
        "python-libguestfs-1.36.10-6.2.vz7.12",
        "python-ploop-7.0.137-1.vz7",
        "python-subprocess32-3.2.7-1.vz7.5",
        "qemu-img-vz-2.10.0-21.7.vz7.67",
        "qemu-kvm-common-vz-2.10.0-21.7.vz7.67",
        "qemu-kvm-tools-vz-2.10.0-21.7.vz7.67",
        "qemu-kvm-vz-2.10.0-21.7.vz7.67",
        "qt-4.8.7-2.vz7.2",
        "qt-assistant-4.8.7-2.vz7.2",
        "qt-config-4.8.7-2.vz7.2",
        "qt-demos-4.8.7-2.vz7.2",
        "qt-devel-4.8.7-2.vz7.2",
        "qt-devel-private-4.8.7-2.vz7.2",
        "qt-doc-4.8.7-2.vz7.2",
        "qt-examples-4.8.7-2.vz7.2",
        "qt-mysql-4.8.7-2.vz7.2",
        "qt-odbc-4.8.7-2.vz7.2",
        "qt-postgresql-4.8.7-2.vz7.2",
        "qt-qdbusviewer-4.8.7-2.vz7.2",
        "qt-qvfb-4.8.7-2.vz7.2",
        "qt-x11-4.8.7-2.vz7.2",
        "readykernel-7.62-1.vl7",
        "readykernel-anaconda-addon-0.6-2.vz7",
        "rmond-7.0.10-1.vz7",
        "ruby-libguestfs-1.36.10-6.2.vz7.12",
        "shaman-7.0.46-1.vz7",
        "sles-15-x86_64-ez-7.0.0-2.vz7",
        "vautomator-ui-anaconda-addon-0.27-2.vz7",
        "vcmmd-7.0.160-1.vz7",
        "vcmmd-policies-7.0.67-1.vz7",
        "virt-dib-1.36.10-6.2.vz7.12",
        "virt-p2v-maker-1.36.10-6.2.vz7.12",
        "virt-v2v-1.36.10-6.2.vz7.12",
        "virtuozzo-release-7.0.9-7.vz7",
        "vstorage-chunk-server-7.8.347.3-6.vz7",
        "vstorage-client-7.8.347.3-6.vz7",
        "vstorage-client-devel-7.8.347.3-6.vz7",
        "vstorage-core-devel-7.8.347.3-6.vz7",
        "vstorage-core-golang-7.8.347.3-6.vz7",
        "vstorage-core-golang-test-7.8.347.3-6.vz7",
        "vstorage-ctl-7.8.347.3-6.vz7",
        "vstorage-devel-7.8.347.3-6.vz7",
        "vstorage-firewall-cfg-7.8.347.3-6.vz7",
        "vstorage-iscsi-7.8.347.3-6.vz7",
        "vstorage-libs-shared-7.8.347.3-6.vz7",
        "vstorage-metadata-server-7.8.347.3-6.vz7",
        "vstorage-ostor-7.6.90-1.vz7",
        "vstorage-ostor-devel-7.6.90-1.vz7",
        "vstorage-ostor-nfs-7.6.90-1.vz7",
        "vstorage-tests-7.8.347.3-6.vz7",
        "vstorage-ui-1.4.28-1.vz7",
        "vstorage-ui-agent-1.3.177.2-1.vz7",
        "vstorage-ui-anaconda-addon-0.41-2.vz7",
        "vstorage-ui-backend-1.3.185.3-3.vz7",
        "vz-docs-7.1.26-2.vz7",
        "vz-guest-tools-lin-7.9-13.vz7",
        "vz-guest-tools-updater-1.0.80-1.vz7",
        "vz-guest-tools-win-7.9-9.vz7",
        "vzctl-7.0.194-1.vz7",
        "vzkernel-3.10.0-862.20.2.vz7.73.29",
        "vzkernel-debug-3.10.0-862.20.2.vz7.73.29",
        "vzkernel-debug-devel-3.10.0-862.20.2.vz7.73.29",
        "vzkernel-devel-3.10.0-862.20.2.vz7.73.29",
        "vzkernel-headers-3.10.0-862.20.2.vz7.73.29",
        "vzlicutils-7.0.58-1.vz7",
        "vzmigrate-7.0.114-1.vz7",
        "vzreport-7.0.15-1.vz7",
        "vzstat-7.0.19-1.vz7",
        "vztt-7.0.63-1.vz7",
        "vztt-devel-7.0.63-1.vz7",
        "vztt-lib-7.0.63-1.vz7",
        "vztt_checker-7.0.2-1.vz7",
        "yum-plugin-scst-0.3-1.vz7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OVMF / anaconda / anaconda-core / anaconda-dracut / etc");
}
