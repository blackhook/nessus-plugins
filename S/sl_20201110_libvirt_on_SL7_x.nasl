##
# (C) Tenable Network Security, Inc.
##
# The descriptive text is (C) Scientific Linux.
#

include('compat.inc');

if (description)
{
  script_id(142821);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/24");

  script_cve_id("CVE-2020-25637");
  script_xref(name:"RHSA", value:"RHSA-2020:5040");

  script_name(english:"Scientific Linux Security Update : libvirt on SL7.x i686/x86_64 (2020:5040)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Scientific Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
SLSA-2020:5040-1 advisory.

  - libvirt: double free in qemuAgentGetInterfaces() in qemu_agent.c (CVE-2020-25637)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.scientificlinux.org/category/sl-errata/slsa-20205040-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25637");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fermilab:scientific_linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-nss");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Scientific Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Scientific Linux' >!< release) audit(AUDIT_OS_NOT, 'Scientific Linux');
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Scientific Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Scientific Linux 7.x', 'Scientific Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Scientific Linux', cpu);

pkgs = [
    {'reference':'libvirt-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-admin-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-bash-completion-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-client-4.5.0-36.el7_9.3', 'cpu':'i686', 'release':'SL7'},
    {'reference':'libvirt-client-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-config-network-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-config-nwfilter-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-driver-interface-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-driver-lxc-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-driver-network-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-driver-nodedev-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-driver-nwfilter-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-driver-qemu-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-driver-secret-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-driver-storage-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-driver-storage-core-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-driver-storage-disk-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-driver-storage-gluster-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-driver-storage-iscsi-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-driver-storage-logical-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-driver-storage-mpath-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-driver-storage-rbd-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-driver-storage-scsi-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-kvm-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-daemon-lxc-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-debuginfo-4.5.0-36.el7_9.3', 'cpu':'i686', 'release':'SL7'},
    {'reference':'libvirt-debuginfo-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-devel-4.5.0-36.el7_9.3', 'cpu':'i686', 'release':'SL7'},
    {'reference':'libvirt-devel-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-docs-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-libs-4.5.0-36.el7_9.3', 'cpu':'i686', 'release':'SL7'},
    {'reference':'libvirt-libs-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-lock-sanlock-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-login-shell-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libvirt-nss-4.5.0-36.el7_9.3', 'cpu':'i686', 'release':'SL7'},
    {'reference':'libvirt-nss-4.5.0-36.el7_9.3', 'cpu':'x86_64', 'release':'SL7'}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
