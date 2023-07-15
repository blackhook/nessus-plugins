#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2023:3822. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177667);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/27");

  script_cve_id("CVE-2023-2700");
  script_xref(name:"RHSA", value:"2023:3822");

  script_name(english:"CentOS 8 : virt:rhel and virt-devel:rhel (CESA-2023:3822)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
CESA-2023:3822 advisory.

  - A vulnerability was found in libvirt. This security flaw ouccers due to repeatedly querying an SR-IOV PCI
    device's capabilities that exposes a memory leak caused by a failure to free the virPCIVirtualFunction
    array within the parent struct's g_autoptr cleanup. (CVE-2023-2700)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:3822");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2700");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-winsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-basic-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-curl-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-example-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-gzip-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-gzip-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-linuxdisk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-nbd-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-python-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-ssh-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-tar-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-tar-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-tmpdisk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-vddk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdkit-xz-filter");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ('CentOS Stream' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
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
      {'reference':'libguestfs-winsupport-8.8-1.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-winsupport-8.8-1.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-bash-completion-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-bash-completion-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-filters-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-filters-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-plugins-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-plugins-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-curl-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-curl-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-devel-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-devel-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-example-plugins-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-example-plugins-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-filter-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-filter-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-linuxdisk-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-linuxdisk-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-nbd-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-nbd-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-python-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-python-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-server-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-server-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-ssh-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-ssh-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tar-filter-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tar-filter-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tar-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tar-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tmpdisk-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tmpdisk-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-vddk-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-vddk-plugin-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-xz-filter-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-xz-filter-1.24.0-5.module_el8.8.0+1257+0c3374ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libguestfs-winsupport / nbdkit / nbdkit-bash-completion / etc');
}
