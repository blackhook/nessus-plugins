#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102134);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_name(english:"Virtuozzo 7 : OVMF / anaconda / anaconda-core / anaconda-dracut / etc (VZA-2017-066)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the OVMF / anaconda / anaconda-core /
anaconda-dracut / etc packages installed, the Virtuozzo installation
on the remote host is affected by the following vulnerabilities :

  - A vulnerability was found in the signal handling in the
    Linux kernel. A local unprivileged user could cause a
    kernel crash (general protection fault) in the
    cleanup_timers() function by using the
    rt_tgsigqueueinfo() system call with a specially
    crafted set of arguments.

  - A privileged user inside a container could cause a
    kernel crash by triggering a GPF in rt6_device_match by
    executing specially crafted code.

  - If the sctp module was loaded on the host, a privileged
    user inside a container could cause a kernel crash by
    triggering a NULL pointer dererefence in the
    sctp_endpoint_destroy() function with a specially
    crafted sequence of system calls.

  - A privileged user inside a container could cause a
    kernel crash by triggering a BUG_ON in the
    unregister_netdevice_many() function with a specially
    crafted sequence of system calls.

  - A vulnerability was found in the implementation of
    setsockopt() operations in the Linux kernel. A
    privileged user inside a container could cause a DoS
    attack on the host (kernel deadlock in ip_ra_control()
    function) using a specially crafted sequence of system
    calls.

  - If the sctp module was loaded on the host, a privileged
    user inside a container could make sctp listen on a
    socket in an inappropriate state, causing a kernel
    crash (use-after-free in sctp_wait_for_sndbuf()).

  - A privileged user inside a container could cause a
    kernel crash by triggering a GPF in
    irq_bypass_unregister_consumer by executing specially
    crafted code.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2852161");
  script_set_attribute(attribute:"solution", value:
"Update the affected OVMF / anaconda / anaconda-core / anaconda-dracut / etc packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/03");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:archive3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:buse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:centos-7-x86_64-ez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:coripper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:cpupools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:cpupools-features");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:criu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:csd_firewalld");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:debian-8.0-x86_64-ez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:debian-9.0-x86_64-ez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:disp-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:disp-helper-ka-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:hastart");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprl-backup-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprl-backup-compat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlcommon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlxmlmodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlxmlmodel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreport-plugin-problem-report");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvcmmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvcmmd-devel");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzevent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzsock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzsock-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:pcompact");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:pdrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:pfcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:phaul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-backup-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-service-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-vzvncserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prlcompress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prlcompress-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prlcompress-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prlctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:pykickstart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-blivet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-ploop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-img-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-common-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-tools-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:readykernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:readykernel-scan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:seabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:seavgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:shaman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:spfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vautomator-ui-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vcmmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vcmmd-policies");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virt-p2v-maker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virt-v2v");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virtuozzo-logos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virtuozzo-motd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virtuozzo-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vmauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-chunk-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-core-golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-firewall-cfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-libs-shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-metadata-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ostor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui-user-s3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-cloudinit");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzprocps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzreport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzstat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vztt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vztt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vztt-lib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["OVMF-20170228-4.gitc325e41585e3.vz7.6",
        "anaconda-21.48.22.93-1.vz7.81",
        "anaconda-core-21.48.22.93-1.vz7.81",
        "anaconda-dracut-21.48.22.93-1.vz7.81",
        "anaconda-gui-21.48.22.93-1.vz7.81",
        "anaconda-tui-21.48.22.93-1.vz7.81",
        "anaconda-widgets-21.48.22.93-1.vz7.81",
        "anaconda-widgets-devel-21.48.22.93-1.vz7.81",
        "archive3-1.2.14-1.as7",
        "archive3-devel-1.2.14-1.as7",
        "buse-7.0.11-1.vz7",
        "centos-7-x86_64-ez-7.0.0-23.vz7",
        "coripper-1.0.6-1.vz7",
        "cpupools-7.0.13-1.vz7",
        "cpupools-features-7.0.13-1.vz7",
        "crit-3.0.0.34-1.vz7",
        "criu-3.0.0.34-1.vz7",
        "criu-devel-3.0.0.34-1.vz7",
        "csd_firewalld-0.6-1.vz7",
        "debian-8.0-x86_64-ez-7.0.0-7.vz7",
        "debian-9.0-x86_64-ez-7.0.0-5.vz7",
        "disp-helper-0.0.41-1.vz7",
        "disp-helper-ka-plugin-0.0.4-1.vz7",
        "hastart-1.0.4-1.vz7",
        "ksm-vz-2.6.0-28.3.10.vz7.75",
        "libcompel-3.0.0.34-1.vz7",
        "libcompel-devel-3.0.0.34-1.vz7",
        "libguestfs-1.34.3-2.vz7.14",
        "libguestfs-appliance-1.34.3-2.vz7.14.fc25",
        "libguestfs-bash-completion-1.34.3-2.vz7.14",
        "libguestfs-benchmarking-1.34.3-2.vz7.14",
        "libguestfs-devel-1.34.3-2.vz7.14",
        "libguestfs-gobject-1.34.3-2.vz7.14",
        "libguestfs-gobject-devel-1.34.3-2.vz7.14",
        "libguestfs-gobject-doc-1.34.3-2.vz7.14",
        "libguestfs-inspect-icons-1.34.3-2.vz7.14",
        "libguestfs-java-1.34.3-2.vz7.14",
        "libguestfs-java-devel-1.34.3-2.vz7.14",
        "libguestfs-javadoc-1.34.3-2.vz7.14",
        "libguestfs-man-pages-ja-1.34.3-2.vz7.14",
        "libguestfs-man-pages-uk-1.34.3-2.vz7.14",
        "libguestfs-tools-1.34.3-2.vz7.14",
        "libguestfs-tools-c-1.34.3-2.vz7.14",
        "libprl-backup-compat-7.0.6-2.vz7",
        "libprl-backup-compat-devel-7.0.6-2.vz7",
        "libprlcommon-7.0.111-1.vz7",
        "libprlcommon-devel-7.0.111-1.vz7",
        "libprlsdk-7.0.195-1.vz7",
        "libprlsdk-devel-7.0.195-1.vz7",
        "libprlsdk-headers-7.0.195-1.vz7",
        "libprlsdk-python-7.0.195-1.vz7",
        "libprlxmlmodel-7.0.69-1.vz7",
        "libprlxmlmodel-devel-7.0.69-1.vz7",
        "libreport-plugin-problem-report-1.0.8-1.vz7",
        "libvcmmd-7.0.22-2.vz7",
        "libvcmmd-devel-7.0.22-2.vz7",
        "libvirt-2.4.0-1.vz7.31",
        "libvirt-admin-2.4.0-1.vz7.31",
        "libvirt-client-2.4.0-1.vz7.31",
        "libvirt-daemon-2.4.0-1.vz7.31",
        "libvirt-daemon-config-network-2.4.0-1.vz7.31",
        "libvirt-daemon-config-nwfilter-2.4.0-1.vz7.31",
        "libvirt-daemon-driver-interface-2.4.0-1.vz7.31",
        "libvirt-daemon-driver-lxc-2.4.0-1.vz7.31",
        "libvirt-daemon-driver-network-2.4.0-1.vz7.31",
        "libvirt-daemon-driver-nodedev-2.4.0-1.vz7.31",
        "libvirt-daemon-driver-nwfilter-2.4.0-1.vz7.31",
        "libvirt-daemon-driver-qemu-2.4.0-1.vz7.31",
        "libvirt-daemon-driver-secret-2.4.0-1.vz7.31",
        "libvirt-daemon-driver-storage-2.4.0-1.vz7.31",
        "libvirt-daemon-driver-vz-2.4.0-1.vz7.31",
        "libvirt-daemon-kvm-2.4.0-1.vz7.31",
        "libvirt-daemon-lxc-2.4.0-1.vz7.31",
        "libvirt-daemon-vz-2.4.0-1.vz7.31",
        "libvirt-devel-2.4.0-1.vz7.31",
        "libvirt-docs-2.4.0-1.vz7.31",
        "libvirt-libs-2.4.0-1.vz7.31",
        "libvirt-lock-sanlock-2.4.0-1.vz7.31",
        "libvirt-login-shell-2.4.0-1.vz7.31",
        "libvirt-nss-2.4.0-1.vz7.31",
        "libvzctl-7.0.399-1.vz7",
        "libvzctl-devel-7.0.399-1.vz7",
        "libvzevent-7.0.7-5.vz7",
        "libvzevent-devel-7.0.7-5.vz7",
        "libvzsock-7.0.3-2.vz7",
        "libvzsock-devel-7.0.3-2.vz7",
        "lua-guestfs-1.34.3-2.vz7.14",
        "ocaml-libguestfs-1.34.3-2.vz7.14",
        "ocaml-libguestfs-devel-1.34.3-2.vz7.14",
        "pcompact-7.0.12-3.vz7",
        "pdrs-7.0.24-3.vz7",
        "perl-Sys-Guestfs-1.34.3-2.vz7.14",
        "pfcache-7.0.26-1.vz7",
        "phaul-0.1.41-1.vz7",
        "ploop-7.0.93-1.vz7",
        "ploop-devel-7.0.93-1.vz7",
        "ploop-lib-7.0.93-1.vz7",
        "prl-backup-compat-7.0.6-2.vz7",
        "prl-disp-backup-7.0.41-1.vz7",
        "prl-disp-legacy-7.0.725-2.vz7",
        "prl-disp-service-7.0.725-2.vz7",
        "prl-disp-service-tests-7.0.725-2.vz7",
        "prl-vzvncserver-7.0.15-1.vz7",
        "prlcompress-7.0.3-3.vz7",
        "prlcompress-devel-7.0.3-3.vz7",
        "prlcompress-lib-7.0.3-3.vz7",
        "prlctl-7.0.137-1.vz7",
        "pykickstart-1.99.66.10-1.vz7.10",
        "python-blivet-0.61.15.59-1.vz7.3",
        "python-criu-3.0.0.34-1.vz7",
        "python-libguestfs-1.34.3-2.vz7.14",
        "python-ploop-7.0.93-1.vz7",
        "qemu-img-vz-2.6.0-28.3.10.vz7.75",
        "qemu-kvm-common-vz-2.6.0-28.3.10.vz7.75",
        "qemu-kvm-tools-vz-2.6.0-28.3.10.vz7.75",
        "qemu-kvm-vz-2.6.0-28.3.10.vz7.75",
        "readykernel-7.55-1.vl7",
        "readykernel-scan-0.8-1.vl7",
        "ruby-libguestfs-1.34.3-2.vz7.14",
        "seabios-1.9.1-5.3.2.vz7.7",
        "seabios-bin-1.9.1-5.3.2.vz7.7",
        "seavgabios-bin-1.9.1-5.3.2.vz7.7",
        "shaman-7.0.42-1.vz7",
        "spfs-0.09.003-1.vz7",
        "vautomator-ui-anaconda-addon-0.19-1.vz7",
        "vcmmd-7.0.147-1.vz7",
        "vcmmd-policies-7.0.63-1.vz7",
        "virt-dib-1.34.3-2.vz7.14",
        "virt-p2v-maker-1.34.3-2.vz7.14",
        "virt-v2v-1.34.3-2.vz7.14",
        "virtuozzo-logos-70.0.11-1.vz7",
        "virtuozzo-motd-0.7-2.vz7",
        "virtuozzo-release-7.0.5-16.vz7",
        "vmauth-7.0.10-2.vz7",
        "vstorage-chunk-server-7.5.109-1.vz7",
        "vstorage-client-7.5.109-1.vz7",
        "vstorage-client-devel-7.5.109-1.vz7",
        "vstorage-core-devel-7.5.109-1.vz7",
        "vstorage-core-golang-7.5.109-1.vz7",
        "vstorage-ctl-7.5.109-1.vz7",
        "vstorage-devel-7.5.109-1.vz7",
        "vstorage-firewall-cfg-7.5.109-1.vz7",
        "vstorage-iscsi-7.5.109-1.vz7",
        "vstorage-libs-shared-7.5.109-1.vz7",
        "vstorage-metadata-server-7.5.109-1.vz7",
        "vstorage-ostor-7.5.34-1.vz7",
        "vstorage-tests-7.5.109-1.vz7",
        "vstorage-ui-1.2.169.1-1.vz7",
        "vstorage-ui-agent-1.2.161.1-1.vz7",
        "vstorage-ui-anaconda-addon-0.26-1.vz7",
        "vstorage-ui-backend-1.2.199.1-1.vz7",
        "vstorage-ui-user-s3-1.2.105.2-1.vz7",
        "vz-cloudinit-1.0-3",
        "vz-guest-tools-lin-0.10-115.vz7",
        "vz-guest-tools-updater-1.0.34-1.vz7",
        "vz-guest-tools-win-0.57-1.vz7",
        "vzctl-7.0.165-1.vz7",
        "vzkernel-3.10.0-514.26.1.vz7.33.22",
        "vzkernel-debug-3.10.0-514.26.1.vz7.33.22",
        "vzkernel-debug-devel-3.10.0-514.26.1.vz7.33.22",
        "vzkernel-devel-3.10.0-514.26.1.vz7.33.22",
        "vzkernel-headers-3.10.0-514.26.1.vz7.33.22",
        "vzlicutils-7.0.52-1.vz7",
        "vzmigrate-7.0.86-2.vz7",
        "vzprocps-3.3.10-3.vz7.8",
        "vzreport-7.0.13-2.vz7",
        "vzstat-7.0.16-1.vz7",
        "vztt-7.0.57-2.vz7",
        "vztt-devel-7.0.57-2.vz7",
        "vztt-lib-7.0.57-2.vz7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OVMF / anaconda / anaconda-core / anaconda-dracut / etc");
}
