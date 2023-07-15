#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-7472.
##

include('compat.inc');

if (description)
{
  script_id(167524);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/15");

  script_cve_id(
    "CVE-2021-3507",
    "CVE-2022-0897",
    "CVE-2022-2211",
    "CVE-2022-23645"
  );

  script_name(english:"Oracle Linux 8 : virt:ol / and / virt-devel:ol (ELSA-2022-7472)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-7472 advisory.

  - swtpm is a libtpms-based TPM emulator with socket, character device, and Linux CUSE interface. Versions
    prior to 0.5.3, 0.6.2, and 0.7.1 are vulnerable to out-of-bounds read. A specially crafted header of
    swtpm's state, where the blobheader's hdrsize indicator has an invalid value, may cause an out-of-bounds
    access when the byte array representing the state of the TPM is accessed. This will likely crash swtpm or
    prevent it from starting since the state cannot be understood. Users should upgrade to swtpm v0.5.3,
    v0.6.2, or v0.7.1 to receive a patch. There are currently no known workarounds. (CVE-2022-23645)

  - A heap buffer overflow was found in the floppy disk emulator of QEMU up to 6.0.0 (including). It could
    occur in fdctrl_transfer_handler() in hw/block/fdc.c while processing DMA read data transfers from the
    floppy drive to the guest system. A privileged guest user could use this flaw to crash the QEMU process on
    the host resulting in DoS scenario, or potential information leakage from the host memory. (CVE-2021-3507)

  - A vulnerability was found in libguestfs. This issue occurs while calculating the greatest possible number
    of matching keys in the get_keys() function. This flaw leads to a denial of service, either by mistake or
    malicious actor. (CVE-2022-2211)

  - A flaw was found in the libvirt nwfilter driver. The virNWFilterObjListNumOfNWFilters method failed to
    acquire the driver->nwfilters mutex before iterating over virNWFilterObj instances. There was no
    protection to stop another thread from concurrently modifying the driver->nwfilters object. This flaw
    allows a malicious, unprivileged user to exploit this issue via libvirt's API virConnectNumOfNWFilters to
    crash the network filter management daemon (libvirtd/virtnwfilterd). (CVE-2022-0897)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-7472.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3507");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-appliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-inspect-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-rescue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-rsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-winsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libiscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libiscsi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libiscsi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnbd-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtpms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtpms-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-iscsi-direct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdfuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-basic-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-curl-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-example-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-gzip-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-gzip-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-linuxdisk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-nbd-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-python-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-ssh-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-tar-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-tar-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-tmpdisk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-vddk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-xz-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:netcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:netcf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:netcf-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Sys-Virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-hw-usbredir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-ui-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-ui-spice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seavgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:supermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:supermin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:swtpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:swtpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:swtpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:swtpm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:swtpm-tools-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virt-v2v");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virt-v2v-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virt-v2v-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virt-v2v-man-pages-uk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/virt');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt:ol');
if ('ol' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module virt:' + module_ver);

var appstreams = {
    'virt:ol': [
      {'reference':'hivex-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-devel-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-devel-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-devel-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-appliance-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-appliance-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-bash-completion-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-inspect-icons-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-javadoc-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-man-pages-ja-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-man-pages-uk-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-winsupport-8.6-1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-winsupport-8.6-1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-winsupport-8.6-1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-xfs-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-xfs-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libiscsi-1.18.0-8.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-1.18.0-8.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-1.18.0-8.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-devel-1.18.0-8.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-devel-1.18.0-8.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-devel-1.18.0-8.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-utils-1.18.0-8.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-utils-1.18.0-8.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-utils-1.18.0-8.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-bash-completion-1.6.0-5.module+el8.7.0+20875+5dd40464', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-devel-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-devel-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-devel-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtpms-0.9.1-1.20211126git1ff6fe1f43.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtpms-0.9.1-1.20211126git1ff6fe1f43.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtpms-devel-0.9.1-1.20211126git1ff6fe1f43.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtpms-devel-0.9.1-1.20211126git1ff6fe1f43.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-network-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-network-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-network-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-nwfilter-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-nwfilter-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-nwfilter-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-interface-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-interface-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-interface-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-network-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-network-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-network-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nodedev-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nodedev-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nodedev-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nwfilter-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nwfilter-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nwfilter-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-qemu-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-qemu-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-secret-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-secret-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-secret-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-core-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-core-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-core-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-disk-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-disk-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-disk-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-gluster-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-gluster-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-logical-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-logical-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-logical-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-mpath-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-mpath-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-mpath-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-rbd-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-rbd-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-scsi-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-scsi-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-scsi-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-kvm-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-kvm-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-dbus-1.3.0-2.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-dbus-1.3.0-2.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-dbus-1.3.0-2.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-docs-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-docs-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-docs-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-libs-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-libs-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-libs-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-lock-sanlock-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-lock-sanlock-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-nss-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-nss-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-nss-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-wireshark-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-wireshark-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-wireshark-8.0.0-10.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lua-guestfs-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'lua-guestfs-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nbdfuse-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdfuse-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdfuse-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-bash-completion-1.24.0-4.module+el8.7.0+20875+5dd40464', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-filters-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-filters-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-plugins-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-plugins-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-curl-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-curl-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-devel-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-devel-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-example-plugins-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-example-plugins-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-filter-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-filter-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-linuxdisk-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-linuxdisk-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-nbd-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-nbd-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-python-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-python-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-server-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-server-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-ssh-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-ssh-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tar-filter-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tar-filter-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tar-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tar-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tmpdisk-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tmpdisk-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-vddk-plugin-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-xz-filter-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-xz-filter-1.24.0-4.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-0.2.8-12.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-0.2.8-12.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-0.2.8-12.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-devel-0.2.8-12.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-devel-0.2.8-12.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-devel-0.2.8-12.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-libs-0.2.8-12.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-libs-0.2.8-12.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-libs-0.2.8-12.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-devel-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-devel-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-devel-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libguestfs-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-devel-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-devel-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libnbd-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libnbd-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libnbd-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libnbd-devel-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libnbd-devel-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libnbd-devel-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-hivex-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-hivex-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-hivex-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Guestfs-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Guestfs-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Virt-8.0.0-1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Virt-8.0.0-1.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Virt-8.0.0-1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-hivex-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-hivex-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-hivex-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libguestfs-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libguestfs-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libnbd-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libnbd-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libnbd-1.6.0-5.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-8.0.0-2.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-8.0.0-2.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-8.0.0-2.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qemu-guest-agent-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-guest-agent-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-img-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-img-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-curl-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-curl-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-gluster-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-iscsi-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-iscsi-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-rbd-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-rbd-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-ssh-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-ssh-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-common-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-common-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-core-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-core-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-docs-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-docs-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-hw-usbredir-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-tests-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-tests-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-opengl-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-spice-6.2.0-20.module+el8.7.0+20875+5dd40464.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'ruby-hivex-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-hivex-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-hivex-1.3.18-23.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libguestfs-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ruby-libguestfs-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'seabios-1.16.0-3.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-bin-1.16.0-3.module+el8.7.0+20875+5dd40464', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seavgabios-bin-1.16.0-3.module+el8.7.0+20875+5dd40464', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sgabios-0.20170427git-3.module+el8.7.0+20875+5dd40464', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-0.20170427git-3.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-bin-0.20170427git-3.module+el8.7.0+20875+5dd40464', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'supermin-5.2.1-2.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-5.2.1-2.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-devel-5.2.1-2.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-devel-5.2.1-2.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-0.7.0-4.20211109gitb79fd91.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-0.7.0-4.20211109gitb79fd91.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-devel-0.7.0-4.20211109gitb79fd91.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-devel-0.7.0-4.20211109gitb79fd91.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-libs-0.7.0-4.20211109gitb79fd91.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-libs-0.7.0-4.20211109gitb79fd91.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-0.7.0-4.20211109gitb79fd91.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-0.7.0-4.20211109gitb79fd91.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-pkcs11-0.7.0-4.20211109gitb79fd91.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-pkcs11-0.7.0-4.20211109gitb79fd91.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-dib-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-dib-1.44.0-9.0.1.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-1.42.0-21.module+el8.7.0+20875+5dd40464', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-bash-completion-1.42.0-21.module+el8.7.0+20875+5dd40464', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-man-pages-ja-1.42.0-21.module+el8.7.0+20875+5dd40464', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-man-pages-uk-1.42.0-21.module+el8.7.0+20875+5dd40464', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && _release) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt:ol');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hivex / hivex-devel / libguestfs / etc');
}
