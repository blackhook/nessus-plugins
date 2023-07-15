##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5961.
##

include('compat.inc');

if (description)
{
  script_id(146198);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2020-25637");

  script_name(english:"Oracle Linux 7 : libvirt (ELSA-2020-5961)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2020-5961 advisory.

  - A double free memory issue was found to occur in the libvirt API, in versions before 6.8.0, responsible
    for requesting information about network interfaces of a running QEMU domain. This flaw affects the polkit
    access control driver. Specifically, clients connecting to the read-write socket with limited ACL
    permissions could use this flaw to crash the libvirt daemon, resulting in a denial of service, or
    potentially escalate their privileges on the system. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2020-25637)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-5961.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25637");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-lxc");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-nss");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'libvirt-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-admin-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-admin-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-bash-completion-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-bash-completion-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-client-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-client-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-config-network-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-config-network-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-config-nwfilter-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-config-nwfilter-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-interface-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-interface-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-lxc-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-lxc-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-network-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-network-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-nodedev-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-nodedev-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-nwfilter-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-nwfilter-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-qemu-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-qemu-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-secret-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-secret-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-core-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-core-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-disk-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-disk-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-gluster-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-gluster-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-iscsi-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-iscsi-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-logical-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-logical-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-mpath-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-mpath-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-rbd-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-rbd-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-scsi-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-driver-storage-scsi-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-kvm-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-kvm-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-lxc-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-lxc-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-daemon-qemu-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-daemon-qemu-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-devel-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-devel-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-docs-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-docs-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-libs-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-libs-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-lock-sanlock-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-lock-sanlock-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-login-shell-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-login-shell-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvirt-nss-5.7.0-21.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvirt-nss-5.7.0-21.el7', 'cpu':'x86_64', 'release':'7'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvirt / libvirt-admin / libvirt-bash-completion / etc');
}