##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:1455. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(125872);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2019-10132",
    "CVE-2019-11091"
  );
  script_xref(name:"RHSA", value:"2019:1455");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");

  script_name(english:"RHEL 8 : Advanced Virtualization (RHSA-2019:1455)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2019:1455 advisory.

  - hardware: Microarchitectural Store Buffer Data Sampling (MSBDS) (CVE-2018-12126)

  - hardware: Micro-architectural Load Port Data Sampling - Information Leak (MLPDS) (CVE-2018-12127)

  - hardware: Microarchitectural Fill Buffer Data Sampling (MFBDS) (CVE-2018-12130)

  - libvirt: wrong permissions in systemd admin-sock due to missing SocketMode parameter (CVE-2019-10132)

  - hardware: Microarchitectural Data Sampling Uncacheable Memory (MDSUM) (CVE-2019-11091)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/203.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/226.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/385.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/732.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-12126");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-12127");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-12130");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10132");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11091");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:1455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1646781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1646784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1667782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1705312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1706067");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10132");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(203, 226, 385, 732);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Red Hat' >!< release) audit(AUDIT_OS_NOT, 'Red Hat');
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

repositories = {
    'advanced_virtualization_8_0_el8': [
      'advanced-virt-for-rhel-8-aarch64-debug-rpms',
      'advanced-virt-for-rhel-8-aarch64-rpms',
      'advanced-virt-for-rhel-8-aarch64-source-rpms',
      'advanced-virt-for-rhel-8-s390x-debug-rpms',
      'advanced-virt-for-rhel-8-s390x-rpms',
      'advanced-virt-for-rhel-8-s390x-source-rpms',
      'advanced-virt-for-rhel-8-x86_64-debug-rpms',
      'advanced-virt-for-rhel-8-x86_64-rpms',
      'advanced-virt-for-rhel-8-x86_64-source-rpms'
    ],
    'advanced_virtualization_8_1_el8': [
      'advanced-virt-crb-for-rhel-8-aarch64-debug-rpms',
      'advanced-virt-crb-for-rhel-8-aarch64-rpms',
      'advanced-virt-crb-for-rhel-8-aarch64-source-rpms',
      'advanced-virt-crb-for-rhel-8-s390x-debug-rpms',
      'advanced-virt-crb-for-rhel-8-s390x-rpms',
      'advanced-virt-crb-for-rhel-8-s390x-source-rpms',
      'advanced-virt-crb-for-rhel-8-x86_64-debug-rpms',
      'advanced-virt-crb-for-rhel-8-x86_64-rpms',
      'advanced-virt-crb-for-rhel-8-x86_64-source-rpms',
      'advanced-virt-for-rhel-8-aarch64-debug-rpms',
      'advanced-virt-for-rhel-8-aarch64-rpms',
      'advanced-virt-for-rhel-8-aarch64-source-rpms',
      'advanced-virt-for-rhel-8-s390x-debug-rpms',
      'advanced-virt-for-rhel-8-s390x-rpms',
      'advanced-virt-for-rhel-8-s390x-source-rpms',
      'advanced-virt-for-rhel-8-x86_64-debug-rpms',
      'advanced-virt-for-rhel-8-x86_64-rpms',
      'advanced-virt-for-rhel-8-x86_64-source-rpms'
    ],
    'advanced_virtualization_8_2_el8': [
      'advanced-virt-crb-for-rhel-8-aarch64-debug-rpms',
      'advanced-virt-crb-for-rhel-8-aarch64-rpms',
      'advanced-virt-crb-for-rhel-8-aarch64-source-rpms',
      'advanced-virt-crb-for-rhel-8-s390x-debug-rpms',
      'advanced-virt-crb-for-rhel-8-s390x-rpms',
      'advanced-virt-crb-for-rhel-8-s390x-source-rpms',
      'advanced-virt-crb-for-rhel-8-x86_64-debug-rpms',
      'advanced-virt-crb-for-rhel-8-x86_64-rpms',
      'advanced-virt-crb-for-rhel-8-x86_64-source-rpms',
      'advanced-virt-for-rhel-8-aarch64-debug-rpms',
      'advanced-virt-for-rhel-8-aarch64-rpms',
      'advanced-virt-for-rhel-8-aarch64-source-rpms',
      'advanced-virt-for-rhel-8-s390x-debug-rpms',
      'advanced-virt-for-rhel-8-s390x-rpms',
      'advanced-virt-for-rhel-8-s390x-source-rpms',
      'advanced-virt-for-rhel-8-x86_64-debug-rpms',
      'advanced-virt-for-rhel-8-x86_64-rpms',
      'advanced-virt-for-rhel-8-x86_64-source-rpms'
    ],
    'advanced_virtualization_8_3_el8': [
      'advanced-virt-crb-for-rhel-8-aarch64-debug-rpms',
      'advanced-virt-crb-for-rhel-8-aarch64-rpms',
      'advanced-virt-crb-for-rhel-8-aarch64-source-rpms',
      'advanced-virt-crb-for-rhel-8-s390x-debug-rpms',
      'advanced-virt-crb-for-rhel-8-s390x-rpms',
      'advanced-virt-crb-for-rhel-8-s390x-source-rpms',
      'advanced-virt-crb-for-rhel-8-x86_64-debug-rpms',
      'advanced-virt-crb-for-rhel-8-x86_64-rpms',
      'advanced-virt-crb-for-rhel-8-x86_64-source-rpms',
      'advanced-virt-for-rhel-8-aarch64-debug-rpms',
      'advanced-virt-for-rhel-8-aarch64-rpms',
      'advanced-virt-for-rhel-8-aarch64-source-rpms',
      'advanced-virt-for-rhel-8-s390x-debug-rpms',
      'advanced-virt-for-rhel-8-s390x-rpms',
      'advanced-virt-for-rhel-8-s390x-source-rpms',
      'advanced-virt-for-rhel-8-x86_64-debug-rpms',
      'advanced-virt-for-rhel-8-x86_64-rpms',
      'advanced-virt-for-rhel-8-x86_64-source-rpms'
    ],
    'advanced_virtualization_8_4_el8': [
      'advanced-virt-crb-for-rhel-8-aarch64-debug-rpms',
      'advanced-virt-crb-for-rhel-8-aarch64-rpms',
      'advanced-virt-crb-for-rhel-8-aarch64-source-rpms',
      'advanced-virt-crb-for-rhel-8-s390x-debug-rpms',
      'advanced-virt-crb-for-rhel-8-s390x-rpms',
      'advanced-virt-crb-for-rhel-8-s390x-source-rpms',
      'advanced-virt-crb-for-rhel-8-x86_64-debug-rpms',
      'advanced-virt-crb-for-rhel-8-x86_64-rpms',
      'advanced-virt-crb-for-rhel-8-x86_64-source-rpms',
      'advanced-virt-for-rhel-8-aarch64-debug-rpms',
      'advanced-virt-for-rhel-8-aarch64-rpms',
      'advanced-virt-for-rhel-8-aarch64-source-rpms',
      'advanced-virt-for-rhel-8-s390x-debug-rpms',
      'advanced-virt-for-rhel-8-s390x-source-rpms',
      'advanced-virt-for-rhel-8-x86_64-debug-rpms',
      'advanced-virt-for-rhel-8-x86_64-rpms',
      'advanced-virt-for-rhel-8-x86_64-source-rpms'
    ],
    'advanced_virtualization_8_el8': [
      'advanced-virt-for-rhel-8-aarch64-debug-rpms',
      'advanced-virt-for-rhel-8-aarch64-rpms',
      'advanced-virt-for-rhel-8-aarch64-source-rpms',
      'advanced-virt-for-rhel-8-s390x-debug-rpms',
      'advanced-virt-for-rhel-8-s390x-rpms',
      'advanced-virt-for-rhel-8-s390x-source-rpms',
      'advanced-virt-for-rhel-8-x86_64-debug-rpms',
      'advanced-virt-for-rhel-8-x86_64-rpms',
      'advanced-virt-for-rhel-8-x86_64-source-rpms'
    ]
};

found_repos = NULL;
host_repo_list = get_kb_list('Host/RedHat/repo-list/*');
if (!(empty_or_null(host_repo_list))) {
  found_repos = make_list();
  foreach repo_key (keys(repositories)) {
    foreach repo ( repositories[repo_key] ) {
      if (get_kb_item('Host/RedHat/repo-list/' + repo)) {
        append_element(var:found_repos, value:repo_key);
        break;
      }
    }
  }
  if(empty_or_null(found_repos)) audit(AUDIT_RHSA_NOT_AFFECTED, 'RHSA-2019:1455');
}

module_ver = get_kb_item('Host/RedHat/appstream/virt');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt:8.0.0');
if ('8.0.0' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module virt:' + module_ver);

appstreams = {
    'virt:8.0.0': [
      {'reference':'hivex-1.3.15-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'hivex-1.3.15-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'hivex-1.3.15-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'hivex-devel-1.3.15-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'hivex-devel-1.3.15-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'hivex-devel-1.3.15-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-bash-completion-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-benchmarking-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-benchmarking-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-devel-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-devel-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-devel-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-gfs2-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-gfs2-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-gfs2-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-gobject-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-gobject-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-gobject-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-gobject-devel-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-gobject-devel-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-gobject-devel-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-inspect-icons-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-java-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-java-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-java-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-java-devel-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-java-devel-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-java-devel-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-javadoc-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-man-pages-ja-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-man-pages-uk-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-rescue-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-rescue-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-rescue-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-rsync-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-rsync-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-rsync-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-tools-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-tools-c-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-tools-c-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-tools-c-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-winsupport-8.0-2.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-winsupport-8.0-2.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-winsupport-8.0-2.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-xfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-xfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libguestfs-xfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libiscsi-1.18.0-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libiscsi-1.18.0-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libiscsi-1.18.0-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libiscsi-devel-1.18.0-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libiscsi-devel-1.18.0-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libiscsi-devel-1.18.0-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libiscsi-utils-1.18.0-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libiscsi-utils-1.18.0-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libiscsi-utils-1.18.0-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libssh2-1.8.0-7.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libssh2-1.8.0-7.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libssh2-1.8.0-7.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-admin-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-admin-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-admin-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-bash-completion-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-bash-completion-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-bash-completion-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-client-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-client-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-client-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-config-network-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-config-network-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-config-network-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-config-nwfilter-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-config-nwfilter-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-config-nwfilter-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-interface-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-interface-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-interface-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-network-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-network-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-network-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-nodedev-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-nodedev-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-nodedev-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-nwfilter-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-nwfilter-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-nwfilter-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-qemu-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-qemu-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-qemu-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-secret-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-secret-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-secret-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-core-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-core-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-core-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-disk-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-disk-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-disk-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-gluster-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-gluster-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-gluster-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-iscsi-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-iscsi-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-iscsi-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-logical-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-logical-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-logical-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-mpath-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-mpath-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-mpath-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-rbd-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-rbd-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-rbd-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-scsi-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-scsi-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-driver-storage-scsi-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-kvm-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-kvm-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-daemon-kvm-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-dbus-1.3.0-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-dbus-1.3.0-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-dbus-1.3.0-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-devel-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-devel-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-devel-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-docs-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-docs-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-docs-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-libs-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-libs-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-libs-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-lock-sanlock-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-lock-sanlock-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-lock-sanlock-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-nss-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-nss-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'libvirt-nss-5.0.0-7.1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'lua-guestfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'lua-guestfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'lua-guestfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-bash-completion-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-basic-plugins-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-basic-plugins-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-basic-plugins-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-devel-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-devel-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-devel-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-example-plugins-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-example-plugins-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-example-plugins-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-plugin-gzip-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-plugin-gzip-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-plugin-gzip-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-plugin-python-common-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-plugin-python-common-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-plugin-python-common-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-plugin-python3-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-plugin-python3-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-plugin-python3-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-plugin-vddk-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-plugin-xz-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-plugin-xz-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'nbdkit-plugin-xz-1.4.2-4.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'netcf-0.2.8-10.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'netcf-0.2.8-10.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'netcf-0.2.8-10.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'netcf-devel-0.2.8-10.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'netcf-devel-0.2.8-10.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'netcf-devel-0.2.8-10.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'netcf-libs-0.2.8-10.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'netcf-libs-0.2.8-10.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'netcf-libs-0.2.8-10.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'perl-hivex-1.3.15-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'perl-hivex-1.3.15-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'perl-hivex-1.3.15-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'perl-Sys-Guestfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'perl-Sys-Guestfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'perl-Sys-Guestfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'perl-Sys-Virt-5.0.0-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'perl-Sys-Virt-5.0.0-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'perl-Sys-Virt-5.0.0-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'python3-hivex-1.3.15-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'python3-hivex-1.3.15-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'python3-hivex-1.3.15-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'python3-libguestfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'python3-libguestfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'python3-libguestfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'python3-libvirt-5.0.0-3.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'python3-libvirt-5.0.0-3.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'python3-libvirt-5.0.0-3.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-guest-agent-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-guest-agent-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-guest-agent-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-img-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-img-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-img-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-block-curl-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-block-curl-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-block-curl-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-block-gluster-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-block-iscsi-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-block-iscsi-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-block-iscsi-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-block-rbd-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-block-rbd-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-block-rbd-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-block-ssh-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-block-ssh-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-block-ssh-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-common-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-common-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-common-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-core-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-core-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'qemu-kvm-core-3.1.0-20.module+el8.0.0+3273+6bc1ee54.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'ruby-hivex-1.3.15-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'ruby-hivex-1.3.15-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'ruby-hivex-1.3.15-6.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'ruby-libguestfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'ruby-libguestfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'ruby-libguestfs-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'seabios-1.12.0-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'seabios-bin-1.12.0-1.module+el8.0.0+3273+6bc1ee54', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'seavgabios-bin-1.12.0-1.module+el8.0.0+3273+6bc1ee54', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'sgabios-0.20170427git-2.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'sgabios-bin-0.20170427git-2.module+el8.0.0+3273+6bc1ee54', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'SLOF-20180702-3.git9b7ab2f.module+el8.0.0+3273+6bc1ee54', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'supermin-5.1.19-8.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'supermin-5.1.19-8.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'supermin-5.1.19-8.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'supermin-devel-5.1.19-8.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'supermin-devel-5.1.19-8.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'supermin-devel-5.1.19-8.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'virt-dib-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'virt-dib-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'virt-dib-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'virt-p2v-maker-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']},
      {'reference':'virt-v2v-1.40.2-1.module+el8.0.0+3273+6bc1ee54', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['advanced_virtualization_8_0_el8', 'advanced_virtualization_8_1_el8', 'advanced_virtualization_8_2_el8', 'advanced_virtualization_8_3_el8', 'advanced_virtualization_8_4_el8', 'advanced_virtualization_8_el8']}
    ]
};

flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  appstream = NULL;
  appstream_name = NULL;
  appstream_version = NULL;
  appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      reference = NULL;
      release = NULL;
      sp = NULL;
      cpu = NULL;
      el_string = NULL;
      rpm_spec_vers_cmp = NULL;
      epoch = NULL;
      allowmaj = NULL;
      repo_list = NULL;
      if (!empty_or_null(package_array['repo_list'])) repo_list = package_array['repo_list'];
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'RHEL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && release) {
        repocheck = FALSE;
        if (empty_or_null(found_repos))
        {
          repocheck = TRUE;
        }
        else
        {
          foreach repo (repo_list) {
            if (contains_element(var:found_repos, value:repo))
            {
              repocheck = TRUE;
              break;
            }
          }
        }
        if (repocheck && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt:8.0.0');

if (flag)
{
  if (empty_or_null(host_repo_list)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'SLOF / hivex / hivex-devel / libguestfs / libguestfs-bash-completion / etc');
}
