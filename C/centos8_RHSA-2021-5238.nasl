#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2021:5238. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156237);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2021-3930", "CVE-2021-20257");
  script_xref(name:"RHSA", value:"2021:5238");

  script_name(english:"CentOS 8 : virt:rhel and virt-devel:rhel (CESA-2021:5238)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2021:5238 advisory.

  - QEMU: net: e1000: infinite loop while processing transmit descriptors (CVE-2021-20257)

  - QEMU: off-by-one error in mode_sense_page() in hw/scsi/scsi-disk.c (CVE-2021-3930)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:5238");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:SLOF");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-benchmarking");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-inspect-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-rescue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-rsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-winsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libiscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libiscsi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libiscsi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-iscsi-direct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdfuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-basic-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-curl-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-example-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-gzip-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-linuxdisk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-python-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-ssh-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-vddk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-xz-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netcf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netcf-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Sys-Virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seavgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:supermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:supermin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:virt-v2v");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< os_release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/virt-devel');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt-devel:rhel');
if ('rhel' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module virt-devel:' + module_ver);

var appstreams = {
    'virt-devel:rhel': [
      {'reference':'hivex-1.3.18-21.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-1.3.18-21.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-devel-1.3.18-21.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-devel-1.3.18-21.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-bash-completion-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-bash-completion-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-benchmarking-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-benchmarking-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-devel-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-devel-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gfs2-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gfs2-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gobject-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gobject-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gobject-devel-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gobject-devel-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-inspect-icons-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-inspect-icons-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-java-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-java-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-java-devel-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-java-devel-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-javadoc-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-javadoc-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-man-pages-ja-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-man-pages-ja-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-man-pages-uk-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-man-pages-uk-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-rescue-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-rescue-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-rsync-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-rsync-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-tools-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-tools-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-tools-c-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-tools-c-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-winsupport-8.2-1.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-winsupport-8.2-1.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-xfs-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-xfs-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-1.18.0-8.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-1.18.0-8.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-1.2.2-1.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-1.2.2-1.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-devel-1.2.2-1.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-devel-1.2.2-1.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-admin-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-admin-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-bash-completion-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-bash-completion-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-network-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-network-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-nwfilter-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-nwfilter-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-interface-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-interface-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-network-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-network-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nodedev-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nodedev-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nwfilter-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nwfilter-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-qemu-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-qemu-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-secret-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-secret-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-core-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-core-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-disk-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-disk-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-gluster-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-gluster-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-logical-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-logical-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-mpath-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-mpath-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-rbd-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-rbd-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-scsi-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-scsi-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-kvm-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-kvm-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-dbus-1.3.0-2.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-dbus-1.3.0-2.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-docs-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-docs-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-libs-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-libs-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-lock-sanlock-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-lock-sanlock-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-nss-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-nss-6.0.0-37.module_el8.5.0+1002+36725df2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lua-guestfs-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lua-guestfs-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdfuse-1.2.2-1.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdfuse-1.2.2-1.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-bash-completion-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-bash-completion-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-filters-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-filters-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-plugins-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-plugins-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-curl-plugin-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-curl-plugin-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-devel-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-devel-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-example-plugins-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-example-plugins-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-plugin-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-plugin-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-linuxdisk-plugin-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-linuxdisk-plugin-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-python-plugin-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-python-plugin-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-server-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-server-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-ssh-plugin-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-ssh-plugin-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-vddk-plugin-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-vddk-plugin-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-xz-filter-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-xz-filter-1.16.2-4.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-0.2.8-12.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-0.2.8-12.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-devel-0.2.8-12.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-devel-0.2.8-12.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-libs-0.2.8-12.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-libs-0.2.8-12.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-1.3.18-21.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-1.3.18-21.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-devel-1.3.18-21.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-devel-1.3.18-21.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libguestfs-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libguestfs-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libguestfs-devel-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libguestfs-devel-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libnbd-1.2.2-1.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libnbd-1.2.2-1.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libnbd-devel-1.2.2-1.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libnbd-devel-1.2.2-1.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-hivex-1.3.18-21.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-hivex-1.3.18-21.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Guestfs-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Guestfs-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Virt-6.0.0-1.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Virt-6.0.0-1.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-hivex-1.3.18-21.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-hivex-1.3.18-21.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libguestfs-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libguestfs-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libnbd-1.2.2-1.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libnbd-1.2.2-1.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-6.0.0-1.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-6.0.0-1.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-hivex-1.3.18-21.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-hivex-1.3.18-21.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libguestfs-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libguestfs-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-1.13.0-2.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-1.13.0-2.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-bin-1.13.0-2.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-bin-1.13.0-2.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seavgabios-bin-1.13.0-2.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seavgabios-bin-1.13.0-2.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sgabios-0.20170427git-3.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-0.20170427git-3.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-bin-0.20170427git-3.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-bin-0.20170427git-3.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'SLOF-20191022-3.git899d9883.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'SLOF-20191022-3.git899d9883.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-5.1.19-10.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-5.1.19-10.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-devel-5.1.19-10.module_el8.3.0+555+a55c8938', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-devel-5.1.19-10.module_el8.3.0+555+a55c8938', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-dib-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-dib-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-v2v-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-v2v-1.40.2-28.module_el8.5.0+821+97472045', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
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
    foreach package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt-devel:rhel');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'SLOF / hivex / hivex-devel / libguestfs / libguestfs-bash-completion / etc');
}
