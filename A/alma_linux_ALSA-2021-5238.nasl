#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2021:5238.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158843);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2021-3930", "CVE-2021-20257");
  script_xref(name:"ALSA", value:"2021:5238");
  script_xref(name:"IAVB", value:"2020-B-0075-S");

  script_name(english:"AlmaLinux 8 : virt:rhel and virt-devel:rhel (ALSA-2021:5238)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2021:5238 advisory.

  - An off-by-one error was found in the SCSI device emulation in QEMU. It could occur while processing MODE
    SELECT commands in mode_sense_page() if the 'page' argument was set to MODE_PAGE_ALLS (0x3f). A malicious
    guest could use this flaw to potentially crash QEMU, resulting in a denial of service condition.
    (CVE-2021-3930)

  - An infinite loop flaw was found in the e1000 NIC emulator of the QEMU. This issue occurs while processing
    transmits (tx) descriptors in process_tx_desc if various descriptor fields are initialized with invalid
    values. This flaw allows a guest to consume CPU cycles on the host, resulting in a denial of service. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20257)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2021-5238.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3930");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-benchmarking");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-inspect-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-rescue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-rsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-winsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libiscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libiscsi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libiscsi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-iscsi-direct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdfuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-basic-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-curl-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-example-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-gzip-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-linuxdisk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-python-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-ssh-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-vddk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-xz-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:netcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:netcf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:netcf-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-Sys-Virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:seabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:seavgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:sgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:supermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:supermin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:virt-v2v");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/virt');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt:rhel');
if ('rhel' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module virt:' + module_ver);

var appstreams = {
    'virt:rhel': [
      {'reference':'hivex-1.3.18-21.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-devel-1.3.18-21.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-bash-completion-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-benchmarking-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-inspect-icons-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-javadoc-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-man-pages-ja-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-man-pages-uk-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-winsupport-8.2-1.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-xfs-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libiscsi-1.18.0-8.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-1.2.2-1.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-devel-1.2.2-1.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-admin-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-bash-completion-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-network-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-nwfilter-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-interface-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-network-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nodedev-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nwfilter-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-qemu-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-secret-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-core-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-disk-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-gluster-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-logical-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-mpath-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-rbd-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-scsi-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-kvm-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-dbus-1.3.0-2.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-docs-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-libs-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-lock-sanlock-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-nss-6.0.0-37.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lua-guestfs-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nbdfuse-1.2.2-1.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-1.16.2-4.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-bash-completion-1.16.2-4.module_el8.5.0+2608+72063365', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-filters-1.16.2-4.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-plugins-1.16.2-4.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-curl-plugin-1.16.2-4.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-devel-1.16.2-4.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-example-plugins-1.16.2-4.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-plugin-1.16.2-4.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-linuxdisk-plugin-1.16.2-4.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-python-plugin-1.16.2-4.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-server-1.16.2-4.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-ssh-plugin-1.16.2-4.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-vddk-plugin-1.16.2-4.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-xz-filter-1.16.2-4.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-0.2.8-12.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-devel-0.2.8-12.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-libs-0.2.8-12.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-hivex-1.3.18-21.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Guestfs-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Virt-6.0.0-1.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-hivex-1.3.18-21.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libguestfs-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libnbd-1.2.2-1.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-6.0.0-1.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qemu-guest-agent-4.2.0-59.module_el8.5.0+2608+72063365.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-img-4.2.0-59.module_el8.5.0+2608+72063365.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-4.2.0-59.module_el8.5.0+2608+72063365.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-curl-4.2.0-59.module_el8.5.0+2608+72063365.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-gluster-4.2.0-59.module_el8.5.0+2608+72063365.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-iscsi-4.2.0-59.module_el8.5.0+2608+72063365.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-rbd-4.2.0-59.module_el8.5.0+2608+72063365.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-ssh-4.2.0-59.module_el8.5.0+2608+72063365.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-common-4.2.0-59.module_el8.5.0+2608+72063365.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-core-4.2.0-59.module_el8.5.0+2608+72063365.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'ruby-hivex-1.3.18-21.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libguestfs-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'seabios-1.13.0-2.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-bin-1.13.0-2.module_el8.5.0+2608+72063365', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seavgabios-bin-1.13.0-2.module_el8.5.0+2608+72063365', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sgabios-0.20170427git-3.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-bin-0.20170427git-3.module_el8.5.0+2608+72063365', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'supermin-5.1.19-10.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-devel-5.1.19-10.module_el8.5.0+2608+72063365', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-dib-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-1.40.2-28.module_el8.5.0+2608+72063365.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      var reference = NULL;
      var release = NULL;
      var sp = NULL;
      var cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      var exists_check = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt:rhel');

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hivex / hivex-devel / libguestfs / libguestfs-bash-completion / etc');
}
