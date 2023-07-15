##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:1759.
##

include('compat.inc');

if (description)
{
  script_id(161144);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/17");

  script_cve_id(
    "CVE-2021-3622",
    "CVE-2021-3716",
    "CVE-2021-3748",
    "CVE-2021-3975",
    "CVE-2021-4145",
    "CVE-2021-4158",
    "CVE-2021-20196",
    "CVE-2021-33285",
    "CVE-2021-33286",
    "CVE-2021-33287",
    "CVE-2021-33289",
    "CVE-2021-35266",
    "CVE-2021-35267",
    "CVE-2021-35268",
    "CVE-2021-35269",
    "CVE-2021-39251",
    "CVE-2021-39252",
    "CVE-2021-39253",
    "CVE-2021-39254",
    "CVE-2021-39255",
    "CVE-2021-39256",
    "CVE-2021-39257",
    "CVE-2021-39258",
    "CVE-2021-39259",
    "CVE-2021-39260",
    "CVE-2021-39261",
    "CVE-2021-39262",
    "CVE-2021-39263",
    "CVE-2022-0485"
  );
  script_xref(name:"ALSA", value:"2022:1759");
  script_xref(name:"IAVB", value:"2022-B-0051-S");

  script_name(english:"AlmaLinux 8 : virt:rhel and virt-devel:rhel (ALSA-2022:1759)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2022:1759 advisory.

  - A flaw was found in the hivex library. This flaw allows an attacker to input a specially crafted Windows
    Registry (hive) file, which would cause hivex to recursively call the _get_children() function, leading to
    a stack overflow. The highest threat from this vulnerability is to system availability. (CVE-2021-3622)

  - A flaw was found in nbdkit due to to improperly caching plaintext state across the STARTTLS encryption
    boundary. A MitM attacker could use this flaw to inject a plaintext NBD_OPT_STRUCTURED_REPLY before
    proxying everything else a client sends to the server, potentially leading the client to terminate the NBD
    session. The highest threat from this vulnerability is to system availability. (CVE-2021-3716)

  - A use-after-free vulnerability was found in the virtio-net device of QEMU. It could occur when the
    descriptor's address belongs to the non direct access region, due to num_buffers being set after the
    virtqueue elem has been unmapped. A malicious guest could use this flaw to crash QEMU, resulting in a
    denial of service condition, or potentially execute code on the host with the privileges of the QEMU
    process. (CVE-2021-3748)

  - A NULL pointer dereference issue was found in the block mirror layer of QEMU in versions prior to 6.2.0.
    The `self` pointer is dereferenced in mirror_wait_on_conflicts() without ensuring that it's not NULL. A
    malicious unprivileged user within the guest could use this flaw to crash the QEMU process on the host
    when writing data reaches the threshold of mirroring node. (CVE-2021-4145)

  - A NULL pointer dereference flaw was found in the floppy disk emulator of QEMU. This issue occurs while
    processing read/write ioport commands if the selected floppy drive is not initialized with a block device.
    This flaw allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of
    service. The highest threat from this vulnerability is to system availability. (CVE-2021-20196)

  - In NTFS-3G versions < 2021.8.22, when a specially crafted NTFS attribute is supplied to the function
    ntfs_get_attribute_value, a heap buffer overflow can occur allowing for memory disclosure or denial of
    service. The vulnerability is caused by an out-of-bound buffer access which can be triggered by mounting a
    crafted ntfs partition. The root cause is a missing consistency check after reading an MFT record : the
    bytes_in_use field should be less than the bytes_allocated field. When it is not, the parsing of the
    records proceeds into the wild. (CVE-2021-33285)

  - In NTFS-3G versions < 2021.8.22, when a specially crafted unicode string is supplied in an NTFS image a
    heap buffer overflow can occur and allow for code execution. (CVE-2021-33286)

  - In NTFS-3G versions < 2021.8.22, when specially crafted NTFS attributes are read in the function
    ntfs_attr_pread_i, a heap buffer overflow can occur and allow for writing to arbitrary memory or denial of
    service of the application. (CVE-2021-33287)

  - In NTFS-3G versions < 2021.8.22, when a specially crafted MFT section is supplied in an NTFS image a heap
    buffer overflow can occur and allow for code execution. (CVE-2021-33289)

  - In NTFS-3G versions < 2021.8.22, when a specially crafted NTFS inode pathname is supplied in an NTFS image
    a heap buffer overflow can occur resulting in memory disclosure, denial of service and even code
    execution. (CVE-2021-35266)

  - NTFS-3G versions < 2021.8.22, a stack buffer overflow can occur when correcting differences in the MFT and
    MFTMirror allowing for code execution or escalation of privileges when setuid-root. (CVE-2021-35267)

  - In NTFS-3G versions < 2021.8.22, when a specially crafted NTFS inode is loaded in the function
    ntfs_inode_real_open, a heap buffer overflow can occur allowing for code execution and escalation of
    privileges. (CVE-2021-35268)

  - NTFS-3G versions < 2021.8.22, when a specially crafted NTFS attribute from the MFT is setup in the
    function ntfs_attr_setup_flag, a heap buffer overflow can occur allowing for code execution and escalation
    of privileges. (CVE-2021-35269)

  - A crafted NTFS image can cause a NULL pointer dereference in ntfs_extent_inode_open in NTFS-3G <
    2021.8.22. (CVE-2021-39251)

  - A crafted NTFS image can cause an out-of-bounds read in ntfs_ie_lookup in NTFS-3G < 2021.8.22.
    (CVE-2021-39252)

  - A crafted NTFS image can cause an out-of-bounds read in ntfs_runlists_merge_i in NTFS-3G < 2021.8.22.
    (CVE-2021-39253)

  - A crafted NTFS image can cause an integer overflow in memmove, leading to a heap-based buffer overflow in
    the function ntfs_attr_record_resize, in NTFS-3G < 2021.8.22. (CVE-2021-39254)

  - A crafted NTFS image can trigger an out-of-bounds read, caused by an invalid attribute in
    ntfs_attr_find_in_attrdef, in NTFS-3G < 2021.8.22. (CVE-2021-39255)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_inode_lookup_by_name in NTFS-3G <
    2021.8.22. (CVE-2021-39256)

  - A crafted NTFS image with an unallocated bitmap can lead to a endless recursive function call chain
    (starting from ntfs_attr_pwrite), causing stack consumption in NTFS-3G < 2021.8.22. (CVE-2021-39257)

  - A crafted NTFS image can cause out-of-bounds reads in ntfs_attr_find and ntfs_external_attr_find in
    NTFS-3G < 2021.8.22. (CVE-2021-39258)

  - A crafted NTFS image can trigger an out-of-bounds access, caused by an unsanitized attribute length in
    ntfs_inode_lookup_by_name, in NTFS-3G < 2021.8.22. (CVE-2021-39259)

  - A crafted NTFS image can cause an out-of-bounds access in ntfs_inode_sync_standard_information in NTFS-3G
    < 2021.8.22. (CVE-2021-39260)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_compressed_pwrite in NTFS-3G <
    2021.8.22. (CVE-2021-39261)

  - A crafted NTFS image can cause an out-of-bounds access in ntfs_decompress in NTFS-3G < 2021.8.22.
    (CVE-2021-39262)

  - A crafted NTFS image can trigger a heap-based buffer overflow, caused by an unsanitized attribute in
    ntfs_get_attribute_value, in NTFS-3G < 2021.8.22. (CVE-2021-39263)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2022-1759.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39263");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-appliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-bash-completion");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnbd-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libtpms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libtpms-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdfuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-basic-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-curl-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-example-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-gzip-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-gzip-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-linuxdisk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-nbd-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-python-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-ssh-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-tar-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-tar-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-tmpdisk-plugin");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-hw-usbredir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-ui-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-ui-spice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:seabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:seavgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:sgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:supermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:supermin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:swtpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:swtpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:swtpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:swtpm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:swtpm-tools-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:virt-v2v");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:virt-v2v-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:virt-v2v-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:virt-v2v-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


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
      {'reference':'hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-devel-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-devel-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-appliance-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-appliance-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-bash-completion-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-inspect-icons-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-javadoc-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-man-pages-ja-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-man-pages-uk-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-winsupport-8.6-1.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-winsupport-8.6-1.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-xfs-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-xfs-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libiscsi-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-bash-completion-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-devel-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-devel-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtpms-0.9.1-0.20211126git1ff6fe1f43.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtpms-0.9.1-0.20211126git1ff6fe1f43.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtpms-devel-0.9.1-0.20211126git1ff6fe1f43.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtpms-devel-0.9.1-0.20211126git1ff6fe1f43.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-network-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-network-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-nwfilter-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-nwfilter-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-interface-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-interface-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-network-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-network-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nodedev-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nodedev-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nwfilter-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nwfilter-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-qemu-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-qemu-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-secret-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-secret-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-core-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-core-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-disk-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-disk-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-gluster-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-gluster-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-logical-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-logical-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-mpath-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-mpath-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-rbd-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-rbd-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-scsi-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-scsi-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-kvm-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-kvm-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-dbus-1.3.0-2.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-dbus-1.3.0-2.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-docs-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-docs-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-libs-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-libs-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-lock-sanlock-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-lock-sanlock-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-nss-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-nss-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-wireshark-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-wireshark-8.0.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lua-guestfs-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'lua-guestfs-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nbdfuse-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdfuse-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-bash-completion-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-filters-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-filters-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-plugins-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-plugins-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-curl-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-curl-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-devel-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-devel-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-example-plugins-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-example-plugins-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-filter-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-filter-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-linuxdisk-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-linuxdisk-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-nbd-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-nbd-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-python-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-python-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-server-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-server-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-ssh-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-ssh-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tar-filter-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tar-filter-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tar-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tar-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tmpdisk-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tmpdisk-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-vddk-plugin-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-xz-filter-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-xz-filter-1.24.0-4.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-devel-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-devel-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-libs-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-libs-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Guestfs-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Guestfs-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Virt-8.0.0-1.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Virt-8.0.0-1.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libguestfs-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libguestfs-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libnbd-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libnbd-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-8.0.0-1.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-8.0.0-1.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qemu-guest-agent-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-guest-agent-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-img-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-img-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-curl-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-curl-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-gluster-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-iscsi-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-iscsi-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-rbd-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-rbd-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-ssh-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-ssh-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-common-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-common-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-core-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-core-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-docs-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-docs-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-hw-usbredir-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-opengl-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-spice-6.2.0-11.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'ruby-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libguestfs-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ruby-libguestfs-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'seabios-1.15.0-2.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-bin-1.15.0-2.module_el8.6.0+2880+7d9e3703', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seavgabios-bin-1.15.0-2.module_el8.6.0+2880+7d9e3703', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sgabios-0.20170427git-3.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-bin-0.20170427git-3.module_el8.6.0+2880+7d9e3703', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'supermin-5.2.1-1.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-5.2.1-1.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-devel-5.2.1-1.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-devel-5.2.1-1.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-0.7.0-1.20211109gitb79fd91.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-0.7.0-1.20211109gitb79fd91.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-devel-0.7.0-1.20211109gitb79fd91.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-devel-0.7.0-1.20211109gitb79fd91.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-libs-0.7.0-1.20211109gitb79fd91.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-libs-0.7.0-1.20211109gitb79fd91.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-0.7.0-1.20211109gitb79fd91.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-0.7.0-1.20211109gitb79fd91.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-pkcs11-0.7.0-1.20211109gitb79fd91.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-pkcs11-0.7.0-1.20211109gitb79fd91.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-dib-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-dib-1.44.0-5.module_el8.6.0+2880+7d9e3703.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-1.42.0-18.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-bash-completion-1.42.0-18.module_el8.6.0+2880+7d9e3703', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-man-pages-ja-1.42.0-18.module_el8.6.0+2880+7d9e3703', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-man-pages-uk-1.42.0-18.module_el8.6.0+2880+7d9e3703', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hivex / hivex-devel / libguestfs / libguestfs-appliance / etc');
}
