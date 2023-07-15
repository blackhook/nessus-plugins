##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4676. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142449);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2019-15890",
    "CVE-2019-20485",
    "CVE-2020-1983",
    "CVE-2020-10703",
    "CVE-2020-14301",
    "CVE-2020-14339"
  );
  script_xref(name:"RHSA", value:"2020:4676");

  script_name(english:"RHEL 8 : virt:rhel and virt-devel:rhel (RHSA-2020:4676)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:4676 advisory.

  - QEMU: Slirp: use-after-free during packet reassembly (CVE-2019-15890)

  - libvirt: Potential DoS by holding a monitor job while querying QEMU guest-agent (CVE-2019-20485)

  - libvirt: Potential denial of service via active pool without target path (CVE-2020-10703)

  - libvirt: leak of sensitive cookie information via dumpxml (CVE-2020-14301)

  - libvirt: leak of /dev/mapper/control into QEMU guests (CVE-2020-14339)

  - QEMU: slirp: use-after-free in ip_reass() function in ip_input.c (CVE-2020-1983)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15890");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20485");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1983");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10703");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14301");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14339");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4676");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1749716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1809740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1816650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1829825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1848640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1860069");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14339");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(212, 400, 416, 476, 772);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SLOF");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-benchmarking");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-inspect-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-rescue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-rsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-winsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libiscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libiscsi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libiscsi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-iscsi-direct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdfuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-basic-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-curl-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-example-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-gzip-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-linuxdisk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-python-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-ssh-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-vddk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-xz-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netcf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netcf-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ocaml-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ocaml-hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ocaml-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ocaml-libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Sys-Virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seavgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:supermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:supermin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:virt-v2v");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'virt-devel:rhel': [
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.4/x86_64/appstream/debug',
        'content/aus/rhel8/8.4/x86_64/appstream/os',
        'content/aus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.4/x86_64/baseos/debug',
        'content/aus/rhel8/8.4/x86_64/baseos/os',
        'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/appstream/debug',
        'content/e4s/rhel8/8.4/x86_64/appstream/os',
        'content/e4s/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/baseos/debug',
        'content/e4s/rhel8/8.4/x86_64/baseos/os',
        'content/e4s/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.4/x86_64/highavailability/os',
        'content/e4s/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/sap/debug',
        'content/e4s/rhel8/8.4/x86_64/sap/os',
        'content/e4s/rhel8/8.4/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/appstream/debug',
        'content/eus/rhel8/8.4/aarch64/appstream/os',
        'content/eus/rhel8/8.4/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/baseos/debug',
        'content/eus/rhel8/8.4/aarch64/baseos/os',
        'content/eus/rhel8/8.4/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/highavailability/debug',
        'content/eus/rhel8/8.4/aarch64/highavailability/os',
        'content/eus/rhel8/8.4/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/supplementary/debug',
        'content/eus/rhel8/8.4/aarch64/supplementary/os',
        'content/eus/rhel8/8.4/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/appstream/debug',
        'content/eus/rhel8/8.4/x86_64/appstream/os',
        'content/eus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/baseos/debug',
        'content/eus/rhel8/8.4/x86_64/baseos/os',
        'content/eus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/highavailability/debug',
        'content/eus/rhel8/8.4/x86_64/highavailability/os',
        'content/eus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/sap/debug',
        'content/eus/rhel8/8.4/x86_64/sap/os',
        'content/eus/rhel8/8.4/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/supplementary/debug',
        'content/eus/rhel8/8.4/x86_64/supplementary/os',
        'content/eus/rhel8/8.4/x86_64/supplementary/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/appstream/debug',
        'content/tus/rhel8/8.4/x86_64/appstream/os',
        'content/tus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/baseos/debug',
        'content/tus/rhel8/8.4/x86_64/baseos/os',
        'content/tus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/highavailability/debug',
        'content/tus/rhel8/8.4/x86_64/highavailability/os',
        'content/tus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/nfv/debug',
        'content/tus/rhel8/8.4/x86_64/nfv/os',
        'content/tus/rhel8/8.4/x86_64/nfv/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/rt/debug',
        'content/tus/rhel8/8.4/x86_64/rt/os',
        'content/tus/rhel8/8.4/x86_64/rt/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'hivex-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'hivex-devel-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libguestfs-winsupport-8.2-1.module+el8.3.0+6423+e4cb6418', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libiscsi-1.18.0-8.module+el8.1.0+4066+0f1aadab', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libiscsi-devel-1.18.0-8.module+el8.1.0+4066+0f1aadab', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libiscsi-utils-1.18.0-8.module+el8.1.0+4066+0f1aadab', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libnbd-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libnbd-devel-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-admin-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-bash-completion-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-client-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-config-network-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-config-nwfilter-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-interface-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-network-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-nodedev-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-nwfilter-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-secret-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-core-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-disk-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-iscsi-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-iscsi-direct-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-logical-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-mpath-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-rbd-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-scsi-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-dbus-1.3.0-2.module+el8.3.0+6423+e4cb6418', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-devel-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-docs-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-libs-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-nss-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdfuse-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'netcf-0.2.8-12.module+el8.1.0+4066+0f1aadab', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'netcf-devel-0.2.8-12.module+el8.1.0+4066+0f1aadab', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'netcf-libs-0.2.8-12.module+el8.1.0+4066+0f1aadab', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ocaml-hivex-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ocaml-hivex-devel-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ocaml-libguestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'ocaml-libguestfs-devel-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'ocaml-libnbd-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ocaml-libnbd-devel-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'perl-hivex-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'perl-Sys-Virt-6.0.0-1.module+el8.3.0+6423+e4cb6418', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-hivex-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-libnbd-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-libvirt-6.0.0-1.module+el8.3.0+6423+e4cb6418', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'qemu-kvm-tests-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'ruby-hivex-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'sgabios-0.20170427git-3.module+el8.1.0+4066+0f1aadab', 'sp':'4', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
      ]
    },
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.6/x86_64/appstream/debug',
        'content/aus/rhel8/8.6/x86_64/appstream/os',
        'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.6/x86_64/baseos/debug',
        'content/aus/rhel8/8.6/x86_64/baseos/os',
        'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/appstream/debug',
        'content/e4s/rhel8/8.6/x86_64/appstream/os',
        'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/baseos/debug',
        'content/e4s/rhel8/8.6/x86_64/baseos/os',
        'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.6/x86_64/highavailability/os',
        'content/e4s/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/sap/debug',
        'content/e4s/rhel8/8.6/x86_64/sap/os',
        'content/e4s/rhel8/8.6/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/appstream/debug',
        'content/eus/rhel8/8.6/aarch64/appstream/os',
        'content/eus/rhel8/8.6/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/baseos/debug',
        'content/eus/rhel8/8.6/aarch64/baseos/os',
        'content/eus/rhel8/8.6/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/highavailability/debug',
        'content/eus/rhel8/8.6/aarch64/highavailability/os',
        'content/eus/rhel8/8.6/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/supplementary/debug',
        'content/eus/rhel8/8.6/aarch64/supplementary/os',
        'content/eus/rhel8/8.6/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/appstream/debug',
        'content/eus/rhel8/8.6/x86_64/appstream/os',
        'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/baseos/debug',
        'content/eus/rhel8/8.6/x86_64/baseos/os',
        'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/highavailability/debug',
        'content/eus/rhel8/8.6/x86_64/highavailability/os',
        'content/eus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/sap/debug',
        'content/eus/rhel8/8.6/x86_64/sap/os',
        'content/eus/rhel8/8.6/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/supplementary/debug',
        'content/eus/rhel8/8.6/x86_64/supplementary/os',
        'content/eus/rhel8/8.6/x86_64/supplementary/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/appstream/debug',
        'content/tus/rhel8/8.6/x86_64/appstream/os',
        'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/baseos/debug',
        'content/tus/rhel8/8.6/x86_64/baseos/os',
        'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/highavailability/debug',
        'content/tus/rhel8/8.6/x86_64/highavailability/os',
        'content/tus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/rt/os',
        'content/tus/rhel8/8.6/x86_64/rt/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'hivex-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'hivex-devel-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libguestfs-winsupport-8.2-1.module+el8.3.0+6423+e4cb6418', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libiscsi-1.18.0-8.module+el8.1.0+4066+0f1aadab', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libiscsi-devel-1.18.0-8.module+el8.1.0+4066+0f1aadab', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libiscsi-utils-1.18.0-8.module+el8.1.0+4066+0f1aadab', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libnbd-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libnbd-devel-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-admin-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-bash-completion-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-client-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-config-network-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-config-nwfilter-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-interface-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-network-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-nodedev-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-nwfilter-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-secret-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-core-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-disk-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-iscsi-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-iscsi-direct-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-logical-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-mpath-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-rbd-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-scsi-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-dbus-1.3.0-2.module+el8.3.0+6423+e4cb6418', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-devel-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-docs-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-libs-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-nss-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdfuse-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'netcf-0.2.8-12.module+el8.1.0+4066+0f1aadab', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'netcf-devel-0.2.8-12.module+el8.1.0+4066+0f1aadab', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'netcf-libs-0.2.8-12.module+el8.1.0+4066+0f1aadab', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ocaml-hivex-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ocaml-hivex-devel-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ocaml-libguestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'ocaml-libguestfs-devel-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'ocaml-libnbd-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ocaml-libnbd-devel-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'perl-hivex-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'perl-Sys-Virt-6.0.0-1.module+el8.3.0+6423+e4cb6418', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-hivex-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-libnbd-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-libvirt-6.0.0-1.module+el8.3.0+6423+e4cb6418', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'qemu-kvm-tests-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'ruby-hivex-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'sgabios-0.20170427git-3.module+el8.1.0+4066+0f1aadab', 'sp':'6', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
      ]
    },
    {
      'repo_relative_urls': [
        'content/dist/rhel8/8/aarch64/appstream/debug',
        'content/dist/rhel8/8/aarch64/appstream/os',
        'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8/aarch64/baseos/debug',
        'content/dist/rhel8/8/aarch64/baseos/os',
        'content/dist/rhel8/8/aarch64/baseos/source/SRPMS',
        'content/dist/rhel8/8/aarch64/codeready-builder/debug',
        'content/dist/rhel8/8/aarch64/codeready-builder/os',
        'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/aarch64/highavailability/debug',
        'content/dist/rhel8/8/aarch64/highavailability/os',
        'content/dist/rhel8/8/aarch64/highavailability/source/SRPMS',
        'content/dist/rhel8/8/aarch64/supplementary/debug',
        'content/dist/rhel8/8/aarch64/supplementary/os',
        'content/dist/rhel8/8/aarch64/supplementary/source/SRPMS',
        'content/dist/rhel8/8/x86_64/appstream/debug',
        'content/dist/rhel8/8/x86_64/appstream/os',
        'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8/x86_64/baseos/debug',
        'content/dist/rhel8/8/x86_64/baseos/os',
        'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
        'content/dist/rhel8/8/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8/x86_64/codeready-builder/os',
        'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/x86_64/highavailability/debug',
        'content/dist/rhel8/8/x86_64/highavailability/os',
        'content/dist/rhel8/8/x86_64/highavailability/source/SRPMS',
        'content/dist/rhel8/8/x86_64/nfv/debug',
        'content/dist/rhel8/8/x86_64/nfv/os',
        'content/dist/rhel8/8/x86_64/nfv/source/SRPMS',
        'content/dist/rhel8/8/x86_64/resilientstorage/debug',
        'content/dist/rhel8/8/x86_64/resilientstorage/os',
        'content/dist/rhel8/8/x86_64/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/x86_64/rt/debug',
        'content/dist/rhel8/8/x86_64/rt/os',
        'content/dist/rhel8/8/x86_64/rt/source/SRPMS',
        'content/dist/rhel8/8/x86_64/sap-solutions/debug',
        'content/dist/rhel8/8/x86_64/sap-solutions/os',
        'content/dist/rhel8/8/x86_64/sap-solutions/source/SRPMS',
        'content/dist/rhel8/8/x86_64/sap/debug',
        'content/dist/rhel8/8/x86_64/sap/os',
        'content/dist/rhel8/8/x86_64/sap/source/SRPMS',
        'content/dist/rhel8/8/x86_64/supplementary/debug',
        'content/dist/rhel8/8/x86_64/supplementary/os',
        'content/dist/rhel8/8/x86_64/supplementary/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'hivex-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'hivex-devel-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libguestfs-winsupport-8.2-1.module+el8.3.0+6423+e4cb6418', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libiscsi-1.18.0-8.module+el8.1.0+4066+0f1aadab', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libiscsi-devel-1.18.0-8.module+el8.1.0+4066+0f1aadab', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libiscsi-utils-1.18.0-8.module+el8.1.0+4066+0f1aadab', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libnbd-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libnbd-devel-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-admin-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-bash-completion-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-client-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-config-network-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-config-nwfilter-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-interface-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-network-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-nodedev-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-nwfilter-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-secret-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-core-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-disk-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-iscsi-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-iscsi-direct-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-logical-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-mpath-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-rbd-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-scsi-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-dbus-1.3.0-2.module+el8.3.0+6423+e4cb6418', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-devel-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-docs-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-libs-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-nss-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdfuse-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'netcf-0.2.8-12.module+el8.1.0+4066+0f1aadab', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'netcf-devel-0.2.8-12.module+el8.1.0+4066+0f1aadab', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'netcf-libs-0.2.8-12.module+el8.1.0+4066+0f1aadab', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ocaml-hivex-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ocaml-hivex-devel-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ocaml-libguestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'ocaml-libguestfs-devel-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'ocaml-libnbd-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ocaml-libnbd-devel-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'perl-hivex-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'perl-Sys-Virt-6.0.0-1.module+el8.3.0+6423+e4cb6418', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-hivex-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-libnbd-1.2.2-1.module+el8.3.0+7353+9de0a3cc', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-libvirt-6.0.0-1.module+el8.3.0+6423+e4cb6418', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'qemu-kvm-tests-4.2.0-34.module+el8.3.0+7976+077be4ec', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'ruby-hivex-1.3.18-20.module+el8.3.0+6423+e4cb6418', 'cpu':'i686', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'sgabios-0.20170427git-3.module+el8.1.0+4066+0f1aadab', 'cpu':'i686', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
      ]
    }
  ],
  'virt:rhel': [
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.4/x86_64/appstream/debug',
        'content/aus/rhel8/8.4/x86_64/appstream/os',
        'content/aus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.4/x86_64/baseos/debug',
        'content/aus/rhel8/8.4/x86_64/baseos/os',
        'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/appstream/debug',
        'content/e4s/rhel8/8.4/x86_64/appstream/os',
        'content/e4s/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/baseos/debug',
        'content/e4s/rhel8/8.4/x86_64/baseos/os',
        'content/e4s/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.4/x86_64/highavailability/os',
        'content/e4s/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/sap/debug',
        'content/e4s/rhel8/8.4/x86_64/sap/os',
        'content/e4s/rhel8/8.4/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/appstream/debug',
        'content/eus/rhel8/8.4/aarch64/appstream/os',
        'content/eus/rhel8/8.4/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/baseos/debug',
        'content/eus/rhel8/8.4/aarch64/baseos/os',
        'content/eus/rhel8/8.4/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/highavailability/debug',
        'content/eus/rhel8/8.4/aarch64/highavailability/os',
        'content/eus/rhel8/8.4/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/supplementary/debug',
        'content/eus/rhel8/8.4/aarch64/supplementary/os',
        'content/eus/rhel8/8.4/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/appstream/debug',
        'content/eus/rhel8/8.4/x86_64/appstream/os',
        'content/eus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/baseos/debug',
        'content/eus/rhel8/8.4/x86_64/baseos/os',
        'content/eus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/highavailability/debug',
        'content/eus/rhel8/8.4/x86_64/highavailability/os',
        'content/eus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/sap/debug',
        'content/eus/rhel8/8.4/x86_64/sap/os',
        'content/eus/rhel8/8.4/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/supplementary/debug',
        'content/eus/rhel8/8.4/x86_64/supplementary/os',
        'content/eus/rhel8/8.4/x86_64/supplementary/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/appstream/debug',
        'content/tus/rhel8/8.4/x86_64/appstream/os',
        'content/tus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/baseos/debug',
        'content/tus/rhel8/8.4/x86_64/baseos/os',
        'content/tus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/highavailability/debug',
        'content/tus/rhel8/8.4/x86_64/highavailability/os',
        'content/tus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/nfv/debug',
        'content/tus/rhel8/8.4/x86_64/nfv/os',
        'content/tus/rhel8/8.4/x86_64/nfv/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/rt/debug',
        'content/tus/rhel8/8.4/x86_64/rt/os',
        'content/tus/rhel8/8.4/x86_64/rt/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'libguestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-bash-completion-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-benchmarking-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-benchmarking-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-devel-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-gfs2-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-gobject-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-gobject-devel-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-inspect-icons-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-java-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-java-devel-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-javadoc-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-man-pages-ja-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-man-pages-uk-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-rescue-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-rsync-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-tools-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-tools-c-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-xfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libvirt-daemon-driver-qemu-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-gluster-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-kvm-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-lock-sanlock-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'lua-guestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nbdkit-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-bash-completion-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-basic-filters-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-basic-plugins-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-curl-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-devel-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-example-plugins-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-gzip-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-linuxdisk-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-python-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-server-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-ssh-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-vddk-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-xz-filter-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'perl-Sys-Guestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python3-libguestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'qemu-guest-agent-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-img-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-curl-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-gluster-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-iscsi-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-rbd-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-ssh-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-common-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-core-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'ruby-libguestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'seabios-1.13.0-2.module+el8.3.0+7353+9de0a3cc', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'seabios-bin-1.13.0-2.module+el8.3.0+7353+9de0a3cc', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'seavgabios-bin-1.13.0-2.module+el8.3.0+7353+9de0a3cc', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'sgabios-bin-0.20170427git-3.module+el8.1.0+4066+0f1aadab', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'SLOF-20191022-3.git899d9883.module+el8.3.0+6423+e4cb6418', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
        {'reference':'supermin-5.1.19-10.module+el8.3.0+6423+e4cb6418', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'supermin-devel-5.1.19-10.module+el8.3.0+6423+e4cb6418', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'virt-dib-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'virt-v2v-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
      ]
    },
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.6/x86_64/appstream/debug',
        'content/aus/rhel8/8.6/x86_64/appstream/os',
        'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.6/x86_64/baseos/debug',
        'content/aus/rhel8/8.6/x86_64/baseos/os',
        'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/appstream/debug',
        'content/e4s/rhel8/8.6/x86_64/appstream/os',
        'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/baseos/debug',
        'content/e4s/rhel8/8.6/x86_64/baseos/os',
        'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.6/x86_64/highavailability/os',
        'content/e4s/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/sap/debug',
        'content/e4s/rhel8/8.6/x86_64/sap/os',
        'content/e4s/rhel8/8.6/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/appstream/debug',
        'content/eus/rhel8/8.6/aarch64/appstream/os',
        'content/eus/rhel8/8.6/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/baseos/debug',
        'content/eus/rhel8/8.6/aarch64/baseos/os',
        'content/eus/rhel8/8.6/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/highavailability/debug',
        'content/eus/rhel8/8.6/aarch64/highavailability/os',
        'content/eus/rhel8/8.6/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/supplementary/debug',
        'content/eus/rhel8/8.6/aarch64/supplementary/os',
        'content/eus/rhel8/8.6/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/appstream/debug',
        'content/eus/rhel8/8.6/x86_64/appstream/os',
        'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/baseos/debug',
        'content/eus/rhel8/8.6/x86_64/baseos/os',
        'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/highavailability/debug',
        'content/eus/rhel8/8.6/x86_64/highavailability/os',
        'content/eus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/sap/debug',
        'content/eus/rhel8/8.6/x86_64/sap/os',
        'content/eus/rhel8/8.6/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/supplementary/debug',
        'content/eus/rhel8/8.6/x86_64/supplementary/os',
        'content/eus/rhel8/8.6/x86_64/supplementary/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/appstream/debug',
        'content/tus/rhel8/8.6/x86_64/appstream/os',
        'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/baseos/debug',
        'content/tus/rhel8/8.6/x86_64/baseos/os',
        'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/highavailability/debug',
        'content/tus/rhel8/8.6/x86_64/highavailability/os',
        'content/tus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/rt/os',
        'content/tus/rhel8/8.6/x86_64/rt/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'libguestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-bash-completion-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-benchmarking-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-benchmarking-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-devel-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-gfs2-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-gobject-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-gobject-devel-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-inspect-icons-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-java-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-java-devel-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-javadoc-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-man-pages-ja-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-man-pages-uk-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-rescue-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-rsync-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-tools-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-tools-c-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-xfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libvirt-daemon-driver-qemu-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-gluster-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-kvm-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-lock-sanlock-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'lua-guestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nbdkit-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-bash-completion-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-basic-filters-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-basic-plugins-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-curl-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-devel-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-example-plugins-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-gzip-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-linuxdisk-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-python-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-server-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-ssh-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-vddk-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-xz-filter-1.16.2-4.module+el8.3.0+6922+fd575af8', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'perl-Sys-Guestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python3-libguestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'qemu-guest-agent-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-img-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-curl-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-gluster-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-iscsi-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-rbd-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-ssh-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-common-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-core-4.2.0-34.module+el8.3.0+7976+077be4ec', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'ruby-libguestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'seabios-1.13.0-2.module+el8.3.0+7353+9de0a3cc', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'seabios-bin-1.13.0-2.module+el8.3.0+7353+9de0a3cc', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'seavgabios-bin-1.13.0-2.module+el8.3.0+7353+9de0a3cc', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'sgabios-bin-0.20170427git-3.module+el8.1.0+4066+0f1aadab', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'SLOF-20191022-3.git899d9883.module+el8.3.0+6423+e4cb6418', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
        {'reference':'supermin-5.1.19-10.module+el8.3.0+6423+e4cb6418', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'supermin-devel-5.1.19-10.module+el8.3.0+6423+e4cb6418', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'virt-dib-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'virt-v2v-1.40.2-25.module+el8.3.0+7421+642fe24f', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
      ]
    },
    {
      'repo_relative_urls': [
        'content/dist/rhel8/8/aarch64/appstream/debug',
        'content/dist/rhel8/8/aarch64/appstream/os',
        'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8/aarch64/baseos/debug',
        'content/dist/rhel8/8/aarch64/baseos/os',
        'content/dist/rhel8/8/aarch64/baseos/source/SRPMS',
        'content/dist/rhel8/8/aarch64/codeready-builder/debug',
        'content/dist/rhel8/8/aarch64/codeready-builder/os',
        'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/aarch64/highavailability/debug',
        'content/dist/rhel8/8/aarch64/highavailability/os',
        'content/dist/rhel8/8/aarch64/highavailability/source/SRPMS',
        'content/dist/rhel8/8/aarch64/supplementary/debug',
        'content/dist/rhel8/8/aarch64/supplementary/os',
        'content/dist/rhel8/8/aarch64/supplementary/source/SRPMS',
        'content/dist/rhel8/8/x86_64/appstream/debug',
        'content/dist/rhel8/8/x86_64/appstream/os',
        'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8/x86_64/baseos/debug',
        'content/dist/rhel8/8/x86_64/baseos/os',
        'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
        'content/dist/rhel8/8/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8/x86_64/codeready-builder/os',
        'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/x86_64/highavailability/debug',
        'content/dist/rhel8/8/x86_64/highavailability/os',
        'content/dist/rhel8/8/x86_64/highavailability/source/SRPMS',
        'content/dist/rhel8/8/x86_64/nfv/debug',
        'content/dist/rhel8/8/x86_64/nfv/os',
        'content/dist/rhel8/8/x86_64/nfv/source/SRPMS',
        'content/dist/rhel8/8/x86_64/resilientstorage/debug',
        'content/dist/rhel8/8/x86_64/resilientstorage/os',
        'content/dist/rhel8/8/x86_64/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/x86_64/rt/debug',
        'content/dist/rhel8/8/x86_64/rt/os',
        'content/dist/rhel8/8/x86_64/rt/source/SRPMS',
        'content/dist/rhel8/8/x86_64/sap-solutions/debug',
        'content/dist/rhel8/8/x86_64/sap-solutions/os',
        'content/dist/rhel8/8/x86_64/sap-solutions/source/SRPMS',
        'content/dist/rhel8/8/x86_64/sap/debug',
        'content/dist/rhel8/8/x86_64/sap/os',
        'content/dist/rhel8/8/x86_64/sap/source/SRPMS',
        'content/dist/rhel8/8/x86_64/supplementary/debug',
        'content/dist/rhel8/8/x86_64/supplementary/os',
        'content/dist/rhel8/8/x86_64/supplementary/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'libguestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-bash-completion-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-benchmarking-1.40.2-25.module+el8.3.0+7421+642fe24f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-benchmarking-1.40.2-25.module+el8.3.0+7421+642fe24f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-devel-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-gfs2-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-gobject-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-gobject-devel-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-inspect-icons-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-java-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-java-devel-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-javadoc-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-man-pages-ja-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-man-pages-uk-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-rescue-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-rsync-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-tools-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-tools-c-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-xfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libvirt-daemon-driver-qemu-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-gluster-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-kvm-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-lock-sanlock-6.0.0-28.module+el8.3.0+7827+5e65edd7', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'lua-guestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nbdkit-1.16.2-4.module+el8.3.0+6922+fd575af8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-bash-completion-1.16.2-4.module+el8.3.0+6922+fd575af8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-basic-filters-1.16.2-4.module+el8.3.0+6922+fd575af8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-basic-plugins-1.16.2-4.module+el8.3.0+6922+fd575af8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-curl-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-devel-1.16.2-4.module+el8.3.0+6922+fd575af8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-example-plugins-1.16.2-4.module+el8.3.0+6922+fd575af8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-gzip-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-linuxdisk-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-python-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-server-1.16.2-4.module+el8.3.0+6922+fd575af8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-ssh-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-vddk-plugin-1.16.2-4.module+el8.3.0+6922+fd575af8', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-xz-filter-1.16.2-4.module+el8.3.0+6922+fd575af8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'perl-Sys-Guestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python3-libguestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'qemu-guest-agent-4.2.0-34.module+el8.3.0+7976+077be4ec', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-img-4.2.0-34.module+el8.3.0+7976+077be4ec', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-4.2.0-34.module+el8.3.0+7976+077be4ec', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-curl-4.2.0-34.module+el8.3.0+7976+077be4ec', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-gluster-4.2.0-34.module+el8.3.0+7976+077be4ec', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-iscsi-4.2.0-34.module+el8.3.0+7976+077be4ec', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-rbd-4.2.0-34.module+el8.3.0+7976+077be4ec', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-ssh-4.2.0-34.module+el8.3.0+7976+077be4ec', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-common-4.2.0-34.module+el8.3.0+7976+077be4ec', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-core-4.2.0-34.module+el8.3.0+7976+077be4ec', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'ruby-libguestfs-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'seabios-1.13.0-2.module+el8.3.0+7353+9de0a3cc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'seabios-bin-1.13.0-2.module+el8.3.0+7353+9de0a3cc', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'seavgabios-bin-1.13.0-2.module+el8.3.0+7353+9de0a3cc', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'sgabios-bin-0.20170427git-3.module+el8.1.0+4066+0f1aadab', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'SLOF-20191022-3.git899d9883.module+el8.3.0+6423+e4cb6418', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
        {'reference':'supermin-5.1.19-10.module+el8.3.0+6423+e4cb6418', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'supermin-devel-5.1.19-10.module+el8.3.0+6423+e4cb6418', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'virt-dib-1.40.2-25.module+el8.3.0+7421+642fe24f', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'virt-v2v-1.40.2-25.module+el8.3.0+7421+642fe24f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

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
    foreach var module_array ( appstreams[module] ) {
      var repo_relative_urls = NULL;
      if (!empty_or_null(module_array['repo_relative_urls'])) repo_relative_urls = module_array['repo_relative_urls'];
      var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
      foreach var package_array ( module_array['pkgs'] ) {
        var reference = NULL;
        var _release = NULL;
        var sp = NULL;
        var _cpu = NULL;
        var el_string = NULL;
        var rpm_spec_vers_cmp = NULL;
        var epoch = NULL;
        var allowmaj = NULL;
        var exists_check = NULL;
        if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
        if (!empty_or_null(package_array['release'])) _release = 'RHEL' + package_array['release'];
        if (!empty_or_null(package_array['sp']) && !enterprise_linux_flag) sp = package_array['sp'];
        if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
        if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
        if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
        if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
        if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
        if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
        if (reference &&
            _release &&
            rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
            (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
            rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt-devel:rhel / virt:rhel');

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'SLOF / hivex / hivex-devel / libguestfs / libguestfs-bash-completion / etc');
}
