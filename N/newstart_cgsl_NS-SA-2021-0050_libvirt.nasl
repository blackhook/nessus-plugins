##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0050. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147389);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/11");

  script_cve_id("CVE-2020-12430");

  script_name(english:"NewStart CGSL MAIN 6.02 : libvirt Vulnerability (NS-SA-2021-0050)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has libvirt packages installed that are affected by a
vulnerability:

  - An issue was discovered in qemuDomainGetStatsIOThread in qemu/qemu_driver.c in libvirt 4.10.0 though 6.x
    before 6.1.0. A memory leak was found in the virDomainListGetStats libvirt API that is responsible for
    retrieving domain statistics when managing QEMU guests. This flaw allows unprivileged users with a read-
    only connection to cause a memory leak in the domstats command, resulting in a potential denial of
    service. (CVE-2020-12430)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0050");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libvirt packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12430");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 6.02': [
    'libvirt-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-admin-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-admin-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-bash-completion-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-client-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-client-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-config-network-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-config-nwfilter-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-interface-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-interface-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-network-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-network-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-nodedev-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-nodedev-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-nwfilter-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-nwfilter-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-qemu-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-qemu-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-secret-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-secret-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-core-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-core-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-disk-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-disk-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-gluster-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-gluster-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-iscsi-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-iscsi-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-iscsi-direct-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-iscsi-direct-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-logical-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-logical-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-mpath-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-mpath-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-rbd-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-rbd-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-scsi-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-driver-storage-scsi-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-daemon-kvm-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-debugsource-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-devel-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-docs-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-libs-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-libs-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-lock-sanlock-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-lock-sanlock-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-nss-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8',
    'libvirt-nss-debuginfo-5.9.0-2.el8.cgslv6_2.10.165.g3a5ec9f8'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvirt');
}
