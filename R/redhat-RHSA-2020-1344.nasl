##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1344. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(135253);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2020-7039");
  script_xref(name:"RHSA", value:"2020:1344");

  script_name(english:"RHEL 8 : virt:rhel (RHSA-2020:1344)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2020:1344 advisory.

  - QEMU: slirp: OOB buffer access while emulating tcp protocols in tcp_emu() (CVE-2020-7039)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-7039");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1791551");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7039");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.0");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libssh2");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-example-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-plugin-gzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-plugin-python-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-plugin-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-plugin-vddk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-plugin-xz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netcf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netcf-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Sys-Virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libguestfs");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:virt-p2v-maker");
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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.0')) audit(AUDIT_OS_NOT, 'Red Hat 8.0', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'virt:rhel': [
    {
      'repo_relative_urls': [
        'content/e4s/rhel8/8.0/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.0/ppc64le/appstream/os',
        'content/e4s/rhel8/8.0/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.0/ppc64le/baseos/debug',
        'content/e4s/rhel8/8.0/ppc64le/baseos/os',
        'content/e4s/rhel8/8.0/ppc64le/baseos/source/SRPMS',
        'content/e4s/rhel8/8.0/ppc64le/highavailability/debug',
        'content/e4s/rhel8/8.0/ppc64le/highavailability/os',
        'content/e4s/rhel8/8.0/ppc64le/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.0/ppc64le/sap-solutions/debug',
        'content/e4s/rhel8/8.0/ppc64le/sap-solutions/os',
        'content/e4s/rhel8/8.0/ppc64le/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.0/ppc64le/sap/debug',
        'content/e4s/rhel8/8.0/ppc64le/sap/os',
        'content/e4s/rhel8/8.0/ppc64le/sap/source/SRPMS',
        'content/e4s/rhel8/8.0/x86_64/appstream/debug',
        'content/e4s/rhel8/8.0/x86_64/appstream/os',
        'content/e4s/rhel8/8.0/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.0/x86_64/baseos/debug',
        'content/e4s/rhel8/8.0/x86_64/baseos/os',
        'content/e4s/rhel8/8.0/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.0/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.0/x86_64/highavailability/os',
        'content/e4s/rhel8/8.0/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.0/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.0/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.0/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.0/x86_64/sap/debug',
        'content/e4s/rhel8/8.0/x86_64/sap/os',
        'content/e4s/rhel8/8.0/x86_64/sap/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'hivex-1.3.15-7.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'hivex-1.3.15-7.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'hivex-devel-1.3.15-7.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'hivex-devel-1.3.15-7.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libguestfs-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-bash-completion-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-benchmarking-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-devel-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-devel-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-gfs2-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-gfs2-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-gobject-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-gobject-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-gobject-devel-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-gobject-devel-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-inspect-icons-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-java-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-java-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-java-devel-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-java-devel-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-javadoc-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-man-pages-ja-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-man-pages-uk-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-rescue-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-rescue-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-rsync-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-rsync-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-tools-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-tools-c-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-tools-c-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-winsupport-8.0-3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libguestfs-winsupport-8.0-3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libguestfs-xfs-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libguestfs-xfs-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'libiscsi-1.18.0-7.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libiscsi-1.18.0-7.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libiscsi-devel-1.18.0-7.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libiscsi-devel-1.18.0-7.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libiscsi-utils-1.18.0-7.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libiscsi-utils-1.18.0-7.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libssh2-1.8.0-8.module+el8.0.0+4084+cceb9f44.1', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libssh2-1.8.0-8.module+el8.0.0+4084+cceb9f44.1', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-admin-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-admin-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-bash-completion-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-bash-completion-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-client-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-client-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-config-network-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-config-network-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-config-nwfilter-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-config-nwfilter-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-interface-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-interface-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-network-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-network-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-nodedev-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-nodedev-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-nwfilter-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-nwfilter-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-qemu-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-qemu-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-secret-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-secret-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-core-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-core-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-disk-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-disk-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-gluster-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-gluster-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-iscsi-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-iscsi-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-logical-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-logical-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-mpath-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-mpath-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-rbd-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-rbd-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-scsi-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-driver-storage-scsi-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-kvm-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-daemon-kvm-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-dbus-1.2.0-3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-dbus-1.2.0-3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-devel-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-devel-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-docs-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-docs-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-libs-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-libs-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-lock-sanlock-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-lock-sanlock-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-nss-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libvirt-nss-4.5.0-24.3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'lua-guestfs-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'lua-guestfs-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nbdkit-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-bash-completion-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-basic-plugins-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-basic-plugins-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-devel-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-devel-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-example-plugins-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-example-plugins-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-plugin-gzip-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-plugin-gzip-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-plugin-python-common-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-plugin-python-common-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-plugin-python3-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-plugin-python3-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-plugin-vddk-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-plugin-xz-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nbdkit-plugin-xz-1.4.2-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'netcf-0.2.8-11.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'netcf-0.2.8-11.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'netcf-devel-0.2.8-11.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'netcf-devel-0.2.8-11.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'netcf-libs-0.2.8-11.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'netcf-libs-0.2.8-11.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'perl-hivex-1.3.15-7.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'perl-hivex-1.3.15-7.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'perl-Sys-Guestfs-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'perl-Sys-Guestfs-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'perl-Sys-Virt-4.5.0-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'perl-Sys-Virt-4.5.0-5.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-hivex-1.3.15-7.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-hivex-1.3.15-7.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-libguestfs-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python3-libguestfs-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python3-libvirt-4.5.0-2.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-libvirt-4.5.0-2.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'qemu-guest-agent-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-guest-agent-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-img-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-img-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-curl-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-curl-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-gluster-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-iscsi-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-iscsi-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-rbd-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-rbd-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-ssh-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-block-ssh-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-common-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-common-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-core-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'qemu-kvm-core-2.12.0-65.module+el8.0.0+5945+f9bf9a3e.6', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
        {'reference':'ruby-hivex-1.3.15-7.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ruby-hivex-1.3.15-7.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ruby-libguestfs-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'ruby-libguestfs-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'seabios-1.11.1-4.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'seabios-bin-1.11.1-4.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'seavgabios-bin-1.11.1-4.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'sgabios-0.20170427git-3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'sgabios-bin-0.20170427git-3.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'SLOF-20171214-6.gitfa98132.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
        {'reference':'supermin-5.1.19-9.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'supermin-5.1.19-9.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'supermin-devel-5.1.19-9.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'supermin-devel-5.1.19-9.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'virt-dib-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'virt-dib-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'virt-p2v-maker-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'virt-v2v-1.38.4-11.1.module+el8.0.0+4084+cceb9f44', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/virt');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt:rhel');
if ('rhel' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module virt:' + module_ver);

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
        if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt:rhel');

if (flag)
{
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Update Services for SAP Solutions repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
