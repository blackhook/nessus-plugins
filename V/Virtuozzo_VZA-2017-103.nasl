#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104673);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_name(english:"Virtuozzo 7 : OVMF / am_storage / anaconda / anaconda-core / etc (VZA-2017-103)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the OVMF / am_storage / anaconda /
anaconda-core / etc packages installed, the Virtuozzo installation on
the remote host is affected by the following vulnerability :

  - Downloadable ISO images of Virtuozzo as well as their
    MD5 and SHA256 checksums can now be verified against
    the GPG key stored at a secure location. For more
    details, see https://docs.virtuozzo.com/keys/.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2904307");
  script_set_attribute(attribute:"solution", value:
"Update the affected OVMF / am_storage / anaconda / anaconda-core / etc package.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:OVMF");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:am_storage");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:criu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:debian-9.0-x86_64-ez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:disp-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:hastart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ipxe-bootimgs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ipxe-roms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ipxe-roms-qemu");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlcommon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlxmlmodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlxmlmodel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreport-plugin-problem-report");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreport-plugin-virtuozzo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzctl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzlic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzlic-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:pdrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:pfcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:phaul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disk-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-service-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prlctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:pstorage-scsi-target-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:pykickstart");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:seabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:seavgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:shaman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:spfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:suse-42.3-x86_64-ez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vautomator-ui-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vcmmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virt-p2v-maker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virt-v2v");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virtuozzo-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-anaconda-addon");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ostor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ostor-nfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui-user-s3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-cloudinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-guest-tools-lin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-guest-tools-updater");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-guest-tools-win");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-qemu-engine-updater");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzlicutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzmigrate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzpkgenv410x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzreport");
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

pkgs = ["OVMF-20170228-5.gitc325e41585e3.vz7.8",
        "am_storage-1.0-0.vl7",
        "anaconda-21.48.22.121-1.vz7.26",
        "anaconda-core-21.48.22.121-1.vz7.26",
        "anaconda-dracut-21.48.22.121-1.vz7.26",
        "anaconda-gui-21.48.22.121-1.vz7.26",
        "anaconda-tui-21.48.22.121-1.vz7.26",
        "anaconda-widgets-21.48.22.121-1.vz7.26",
        "anaconda-widgets-devel-21.48.22.121-1.vz7.26",
        "archive3-1.4.38-1.vz7",
        "archive3-devel-1.4.38-1.vz7",
        "buse-7.0.12-1.vz7",
        "crit-3.4.0.25-1.vz7",
        "criu-3.4.0.25-1.vz7",
        "criu-devel-3.4.0.25-1.vz7",
        "debian-9.0-x86_64-ez-7.0.0-9.vz7",
        "disp-helper-0.0.49-1.vz7",
        "hastart-1.0.5-1.vz7",
        "ipxe-bootimgs-20170123-1.git4e85b27.vz7.1",
        "ipxe-roms-20170123-1.git4e85b27.vz7.1",
        "ipxe-roms-qemu-20170123-1.git4e85b27.vz7.1",
        "ksm-vz-2.9.0-16.3.vz7.36",
        "libcompel-3.4.0.25-1.vz7",
        "libcompel-devel-3.4.0.25-1.vz7",
        "libguestfs-1.34.3-2.vz7.19",
        "libguestfs-appliance-1.34.3-2.vz7.19.fc25",
        "libguestfs-bash-completion-1.34.3-2.vz7.19",
        "libguestfs-benchmarking-1.34.3-2.vz7.19",
        "libguestfs-devel-1.34.3-2.vz7.19",
        "libguestfs-gobject-1.34.3-2.vz7.19",
        "libguestfs-gobject-devel-1.34.3-2.vz7.19",
        "libguestfs-gobject-doc-1.34.3-2.vz7.19",
        "libguestfs-inspect-icons-1.34.3-2.vz7.19",
        "libguestfs-java-1.34.3-2.vz7.19",
        "libguestfs-java-devel-1.34.3-2.vz7.19",
        "libguestfs-javadoc-1.34.3-2.vz7.19",
        "libguestfs-man-pages-ja-1.34.3-2.vz7.19",
        "libguestfs-man-pages-uk-1.34.3-2.vz7.19",
        "libguestfs-tools-1.34.3-2.vz7.19",
        "libguestfs-tools-c-1.34.3-2.vz7.19",
        "libprlcommon-7.0.116-1.vz7",
        "libprlcommon-devel-7.0.116-1.vz7",
        "libprlsdk-7.0.198-2.vz7",
        "libprlsdk-devel-7.0.198-2.vz7",
        "libprlsdk-headers-7.0.198-2.vz7",
        "libprlsdk-python-7.0.198-2.vz7",
        "libprlxmlmodel-7.0.71-1.vz7",
        "libprlxmlmodel-devel-7.0.71-1.vz7",
        "libreport-plugin-problem-report-1.0.12-1.vz7",
        "libreport-plugin-virtuozzo-1.0.7-1.vz7",
        "libvirt-3.6.0-1.vz7.17",
        "libvirt-admin-3.6.0-1.vz7.17",
        "libvirt-client-3.6.0-1.vz7.17",
        "libvirt-daemon-3.6.0-1.vz7.17",
        "libvirt-daemon-config-network-3.6.0-1.vz7.17",
        "libvirt-daemon-config-nwfilter-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-interface-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-lxc-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-network-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-nodedev-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-nwfilter-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-qemu-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-secret-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-storage-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-storage-core-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-storage-disk-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-storage-gluster-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-storage-iscsi-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-storage-logical-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-storage-mpath-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-storage-rbd-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-storage-scsi-3.6.0-1.vz7.17",
        "libvirt-daemon-driver-vz-3.6.0-1.vz7.17",
        "libvirt-daemon-kvm-3.6.0-1.vz7.17",
        "libvirt-daemon-lxc-3.6.0-1.vz7.17",
        "libvirt-daemon-vz-3.6.0-1.vz7.17",
        "libvirt-devel-3.6.0-1.vz7.17",
        "libvirt-docs-3.6.0-1.vz7.17",
        "libvirt-libs-3.6.0-1.vz7.17",
        "libvirt-lock-sanlock-3.6.0-1.vz7.17",
        "libvirt-login-shell-3.6.0-1.vz7.17",
        "libvirt-nss-3.6.0-1.vz7.17",
        "libvirt-python-3.6.0-1.vz7.1",
        "libvzctl-7.0.442-1.vz7",
        "libvzctl-devel-7.0.442-1.vz7",
        "libvzlic-7.0.41.1-1.vz7",
        "libvzlic-devel-7.0.41.1-1.vz7",
        "lua-guestfs-1.34.3-2.vz7.19",
        "ocaml-libguestfs-1.34.3-2.vz7.19",
        "ocaml-libguestfs-devel-1.34.3-2.vz7.19",
        "pdrs-7.0.28-1.vz7",
        "perl-Sys-Guestfs-1.34.3-2.vz7.19",
        "pfcache-7.0.27-1.vz7",
        "phaul-0.1.47-1.vz7",
        "ploop-7.0.112-1.vz7",
        "ploop-devel-7.0.112-1.vz7",
        "ploop-lib-7.0.112-1.vz7",
        "prl-disk-tool-7.0.37-1.vz7",
        "prl-disp-backup-7.0.42-1.vz7",
        "prl-disp-legacy-7.0.774-1.vz7",
        "prl-disp-service-7.0.774-1.vz7",
        "prl-disp-service-tests-7.0.774-1.vz7",
        "prlctl-7.0.143-1.vz7",
        "pstorage-scsi-target-utils-1.0.67-21.vz7.1",
        "pykickstart-1.99.66.12-1.vz7.2",
        "python-blivet-0.61.15.65-1.vz7.2",
        "python-criu-3.4.0.25-1.vz7",
        "python-libguestfs-1.34.3-2.vz7.19",
        "python-ploop-7.0.112-1.vz7",
        "python-subprocess32-3.2.6-5.vz7.2",
        "qemu-img-vz-2.9.0-16.3.vz7.36",
        "qemu-kvm-common-vz-2.9.0-16.3.vz7.36",
        "qemu-kvm-tools-vz-2.9.0-16.3.vz7.36",
        "qemu-kvm-vz-2.9.0-16.3.vz7.36",
        "qt-4.8.5-15.vz7.1",
        "qt-assistant-4.8.5-15.vz7.1",
        "qt-config-4.8.5-15.vz7.1",
        "qt-demos-4.8.5-15.vz7.1",
        "qt-devel-4.8.5-15.vz7.1",
        "qt-devel-private-4.8.5-15.vz7.1",
        "qt-doc-4.8.5-15.vz7.1",
        "qt-examples-4.8.5-15.vz7.1",
        "qt-mysql-4.8.5-15.vz7.1",
        "qt-odbc-4.8.5-15.vz7.1",
        "qt-postgresql-4.8.5-15.vz7.1",
        "qt-qdbusviewer-4.8.5-15.vz7.1",
        "qt-qvfb-4.8.5-15.vz7.1",
        "qt-x11-4.8.5-15.vz7.1",
        "readykernel-7.56-1.vl7",
        "ruby-libguestfs-1.34.3-2.vz7.19",
        "seabios-1.10.2-3.vz7.2",
        "seabios-bin-1.10.2-3.vz7.2",
        "seavgabios-bin-1.10.2-3.vz7.2",
        "shaman-7.0.43-1.vz7",
        "spfs-0.09.007-1.vz7",
        "suse-42.3-x86_64-ez-7.0.0-2.vz7",
        "vautomator-ui-anaconda-addon-0.26-1.vz7",
        "vcmmd-7.0.149-1.vz7",
        "virt-dib-1.34.3-2.vz7.19",
        "virt-p2v-maker-1.34.3-2.vz7.19",
        "virt-v2v-1.34.3-2.vz7.19",
        "virtuozzo-release-7.0.6-13.vz7",
        "vstorage-anaconda-addon-0.34-1.vz7",
        "vstorage-chunk-server-7.6.171-1.vz7",
        "vstorage-client-7.6.171-1.vz7",
        "vstorage-client-devel-7.6.171-1.vz7",
        "vstorage-core-devel-7.6.171-1.vz7",
        "vstorage-core-golang-7.6.171-1.vz7",
        "vstorage-ctl-7.6.171-1.vz7",
        "vstorage-devel-7.6.171-1.vz7",
        "vstorage-firewall-cfg-7.6.171-1.vz7",
        "vstorage-iscsi-7.6.171-1.vz7",
        "vstorage-libs-shared-7.6.171-1.vz7",
        "vstorage-metadata-server-7.6.171-1.vz7",
        "vstorage-ostor-7.6.90-1.vz7",
        "vstorage-ostor-devel-7.6.90-1.vz7",
        "vstorage-ostor-nfs-7.6.90-1.vz7",
        "vstorage-tests-7.6.171-1.vz7",
        "vstorage-ui-1.3.159.2-1.vz7",
        "vstorage-ui-agent-1.3.168.1-1.vz7",
        "vstorage-ui-anaconda-addon-0.39-1.vz7",
        "vstorage-ui-backend-1.3.175.2-2.vz7",
        "vstorage-ui-user-s3-1.3.119.1-1.vz7",
        "vz-cloudinit-1.0-4",
        "vz-docs-7.1.26.3-1.vz7",
        "vz-guest-tools-lin-7.6-16.vz7",
        "vz-guest-tools-updater-1.0.61-1.vz7",
        "vz-guest-tools-win-7.6-8.vz7",
        "vz-qemu-engine-updater-0.1.22-1.vz7",
        "vzctl-7.0.173-1.vz7",
        "vzkernel-3.10.0-693.1.1.vz7.37.30",
        "vzkernel-debug-3.10.0-693.1.1.vz7.37.30",
        "vzkernel-debug-devel-3.10.0-693.1.1.vz7.37.30",
        "vzkernel-devel-3.10.0-693.1.1.vz7.37.30",
        "vzkernel-headers-3.10.0-693.1.1.vz7.37.30",
        "vzlicutils-7.0.55-1.vz7",
        "vzmigrate-7.0.93-1.vz7",
        "vzpkgenv410x64-7.0.9-13.vz7",
        "vzreport-7.0.14-1.vz7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OVMF / am_storage / anaconda / anaconda-core / etc");
}
