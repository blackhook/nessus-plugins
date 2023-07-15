##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2020:1358. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145992);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2020-1711", "CVE-2020-7039");
  script_xref(name:"RHSA", value:"2020:1358");

  script_name(english:"CentOS 8 : virt:rhel (CESA-2020:1358)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:1358 advisory.

  - QEMU: block: iscsi: OOB heap access via an unexpected response of iSCSI Server (CVE-2020-1711)

  - QEMU: slirp: OOB buffer access while emulating tcp protocols in tcp_emu() (CVE-2020-7039)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1358");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7039");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1711");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-example-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-plugin-gzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-plugin-python-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-plugin-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-plugin-vddk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-plugin-xz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netcf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netcf-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Sys-Virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-libguestfs");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:virt-p2v-maker");
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
      {'reference':'hivex-1.3.15-7.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-1.3.15-7.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-devel-1.3.15-7.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-devel-1.3.15-7.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-bash-completion-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-bash-completion-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-benchmarking-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-benchmarking-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-devel-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-devel-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gfs2-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gfs2-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gobject-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gobject-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gobject-devel-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gobject-devel-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-inspect-icons-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-inspect-icons-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-java-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-java-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-java-devel-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-java-devel-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-javadoc-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-javadoc-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-man-pages-ja-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-man-pages-ja-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-man-pages-uk-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-man-pages-uk-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-rescue-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-rescue-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-rsync-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-rsync-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-tools-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-tools-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-tools-c-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-tools-c-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-winsupport-8.0-4.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-winsupport-8.0-4.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-xfs-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-xfs-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-1.18.0-8.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-1.18.0-8.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-admin-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-admin-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-bash-completion-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-bash-completion-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-network-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-network-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-nwfilter-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-nwfilter-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-interface-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-interface-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-network-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-network-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nodedev-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nodedev-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nwfilter-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nwfilter-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-qemu-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-qemu-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-secret-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-secret-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-core-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-core-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-disk-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-disk-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-gluster-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-gluster-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-logical-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-logical-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-mpath-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-mpath-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-rbd-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-rbd-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-scsi-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-scsi-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-kvm-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-kvm-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-dbus-1.2.0-3.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-dbus-1.2.0-3.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-docs-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-docs-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-libs-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-libs-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-lock-sanlock-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-lock-sanlock-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-nss-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-nss-4.5.0-35.3.module_el8.1.0+297+df420408', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lua-guestfs-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lua-guestfs-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-bash-completion-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-bash-completion-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-plugins-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-plugins-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-devel-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-devel-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-example-plugins-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-example-plugins-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-plugin-gzip-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-plugin-gzip-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-plugin-python-common-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-plugin-python-common-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-plugin-python3-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-plugin-python3-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-plugin-vddk-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-plugin-vddk-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-plugin-xz-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-plugin-xz-1.4.2-5.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-0.2.8-12.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-0.2.8-12.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-devel-0.2.8-12.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-devel-0.2.8-12.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-libs-0.2.8-12.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-libs-0.2.8-12.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-1.3.15-7.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-1.3.15-7.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-devel-1.3.15-7.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-devel-1.3.15-7.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libguestfs-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libguestfs-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libguestfs-devel-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libguestfs-devel-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-hivex-1.3.15-7.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-hivex-1.3.15-7.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Guestfs-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Guestfs-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Virt-4.5.0-5.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Virt-4.5.0-5.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-hivex-1.3.15-7.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-hivex-1.3.15-7.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libguestfs-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libguestfs-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-4.5.0-2.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-4.5.0-2.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-hivex-1.3.15-7.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-hivex-1.3.15-7.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libguestfs-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libguestfs-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-1.11.1-4.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-1.11.1-4.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-bin-1.11.1-4.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-bin-1.11.1-4.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seavgabios-bin-1.11.1-4.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seavgabios-bin-1.11.1-4.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sgabios-0.20170427git-3.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-0.20170427git-3.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-bin-0.20170427git-3.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-bin-0.20170427git-3.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'SLOF-20171214-6.gitfa98132.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'SLOF-20171214-6.gitfa98132.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-5.1.19-9.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-5.1.19-9.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-devel-5.1.19-9.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-devel-5.1.19-9.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-dib-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-dib-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-p2v-maker-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-p2v-maker-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-v2v-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-v2v-1.38.4-14.module_el8.1.0+248+298dec18', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
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
