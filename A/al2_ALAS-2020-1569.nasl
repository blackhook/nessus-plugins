##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1569.
##

include('compat.inc');

if (description)
{
  script_id(143577);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/09");

  script_cve_id("CVE-2020-25637");
  script_xref(name:"ALAS", value:"2020-1569");

  script_name(english:"Amazon Linux 2 : libvirt (ALAS-2020-1569)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the ALAS2-2020-1569 advisory.

  - A double free memory issue was found to occur in the libvirt API, in versions before 6.8.0, responsible
    for requesting information about network interfaces of a running QEMU domain. This flaw affects the polkit
    access control driver. Specifically, clients connecting to the read-write socket with limited ACL
    permissions could use this flaw to crash the libvirt daemon, resulting in a denial of service, or
    potentially escalate their privileges on the system. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2020-25637)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1569.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25637");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update libvirt' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25637");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'libvirt-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-admin-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-admin-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-admin-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-bash-completion-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-bash-completion-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-bash-completion-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-client-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-client-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-client-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-config-network-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-config-network-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-config-network-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-config-nwfilter-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-config-nwfilter-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-config-nwfilter-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-interface-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-interface-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-interface-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-lxc-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-lxc-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-lxc-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-network-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-network-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-network-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-nodedev-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-nodedev-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-nodedev-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-nwfilter-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-nwfilter-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-nwfilter-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-qemu-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-qemu-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-secret-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-secret-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-secret-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-core-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-core-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-core-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-disk-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-disk-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-disk-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-gluster-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-iscsi-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-iscsi-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-iscsi-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-logical-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-logical-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-logical-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-mpath-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-mpath-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-mpath-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-rbd-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-scsi-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-scsi-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-driver-storage-scsi-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-kvm-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-kvm-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-daemon-lxc-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-daemon-lxc-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-daemon-lxc-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-debuginfo-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-debuginfo-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-debuginfo-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-devel-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-devel-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-devel-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-docs-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-docs-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-docs-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-libs-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-libs-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-libs-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-lock-sanlock-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-lock-sanlock-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-login-shell-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-login-shell-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-login-shell-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvirt-nss-4.5.0-36.amzn2.3', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvirt-nss-4.5.0-36.amzn2.3', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvirt-nss-4.5.0-36.amzn2.3', 'cpu':'x86_64', 'release':'AL2'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-admin / libvirt-bash-completion / etc");
}