#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1834-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151719);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id("CVE-2021-3509", "CVE-2021-3524", "CVE-2021-3531");

  script_name(english:"openSUSE 15 Security Update : ceph (openSUSE-SU-2021:1834-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1834-1 advisory.

  - A flaw was found in Red Hat Ceph Storage 4, in the Dashboard component. In response to CVE-2020-27839, the
    JWT token was moved from localStorage to an httpOnly cookie. However, token cookies are used in the body
    of the HTTP response for the documentation, which again makes it available to XSS.The greatest threat to
    the system is for confidentiality, integrity, and availability. (CVE-2021-3509)

  - A flaw was found in the Red Hat Ceph Storage RadosGW (Ceph Object Gateway) in versions before 14.2.21. The
    vulnerability is related to the injection of HTTP headers via a CORS ExposeHeader tag. The newline
    character in the ExposeHeader tag in the CORS configuration file generates a header injection in the
    response when the CORS request is made. In addition, the prior bug fix for CVE-2020-10753 did not account
    for the use of \r as a header separator, thus a new flaw has been created. (CVE-2021-3524)

  - A flaw was found in the Red Hat Ceph Storage RGW in versions before 14.2.21. When processing a GET Request
    for a swift URL that ends with two slashes it can cause the rgw to crash, resulting in a denial of
    service. The greatest threat to the system is of availability. (CVE-2021-3531)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186021");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OD76XLAQUNHRCX53LARPKA7IODR5MCPO/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a24263d");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3524");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3531");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3524");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-grafana-dashboards");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-immutable-object-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-dashboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-diskprediction-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-diskprediction-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-k8sevents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-rook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-prometheus-alerts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cephfs-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libradospp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rados-objclass-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-nbd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

pkgs = [
    {'reference':'ceph-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-base-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-common-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-fuse-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-grafana-dashboards-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-immutable-object-cache-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-mds-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-mgr-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-mgr-cephadm-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-mgr-dashboard-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-mgr-diskprediction-cloud-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-mgr-diskprediction-local-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-mgr-k8sevents-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-mgr-modules-core-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-mgr-rook-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-mon-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-osd-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-prometheus-alerts-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-radosgw-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ceph-test-15.2.12.83+g528da226523-3.25.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cephadm-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cephfs-shell-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcephfs-devel-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcephfs2-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librados-devel-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librados2-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libradospp-devel-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librbd-devel-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librbd1-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librgw-devel-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librgw2-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ceph-argparse-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ceph-common-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-cephfs-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-rados-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-rbd-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-rgw-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rados-objclass-devel-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rbd-fuse-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rbd-mirror-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rbd-nbd-15.2.12.83+g528da226523-3.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph / ceph-base / ceph-common / ceph-fuse / ceph-grafana-dashboards / etc');
}
