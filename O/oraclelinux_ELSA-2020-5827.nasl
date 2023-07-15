##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5827.
##

include('compat.inc');

if (description)
{
  script_id(140082);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/22");

  script_cve_id("CVE-2020-16845");
  script_xref(name:"IAVB", value:"2020-B-0060-S");

  script_name(english:"Oracle Linux 7 : olcne / conmon / coredns / cri-o / cri-tools / etcd / flannel / grafana / helm / istio / kata / kata-agent / kata-image / kata-ksm-throttler / kata-proxy / kata-runtime / kata-shim / kubernetes / kubernetes-cni / kubernetes-cni-plugins / kubernetes-dashboard / prometheus / yq (ELSA-2020-5827)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2020-5827 advisory.

  - Go before 1.13.15 and 14.x before 1.14.7 can have an infinite read loop in ReadUvarint and ReadVarint in
    encoding/binary via invalid inputs. (CVE-2020-16845)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-5827.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16845");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:coredns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cri-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:etcd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:flannel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grafana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:helm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:istio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:istio-citadel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:istio-galley");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:istio-istioctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:istio-mixc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:istio-mixs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:istio-node-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:istio-pilot-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:istio-pilot-discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:istio-proxy-init");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:istio-sidecar-injector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kata-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kata-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kata-ksm-throttler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kata-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kata-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kata-shim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kubeadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kubectl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kubelet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kubernetes-cni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kubernetes-cni-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kubernetes-dashboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-api-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-istio-chart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-prometheus-chart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcnectl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yq");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'conmon-2.0.10-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'coredns-1.6.5-1.0.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cri-o-1.17.0-1.0.5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cri-o-1.17.'},
    {'reference':'cri-tools-1.17.0-1.0.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'etcd-3.4.3-1.0.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flannel-0.10.0-2.1.12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grafana-6.7.4-1.0.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'helm-3.1.1-1.0.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'istio-1.4.10-1.0.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'istio-citadel-1.4.10-1.0.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'istio-galley-1.4.10-1.0.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'istio-istioctl-1.4.10-1.0.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'istio-mixc-1.4.10-1.0.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'istio-mixs-1.4.10-1.0.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'istio-node-agent-1.4.10-1.0.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'istio-pilot-agent-1.4.10-1.0.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'istio-pilot-discovery-1.4.10-1.0.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'istio-proxy-init-1.4.10-1.0.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'istio-sidecar-injector-1.4.10-1.0.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kata-1.7.3-1.0.9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kata-agent-1.7.3-1.0.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kata-image-1.7.3-1.0.6.1.ol7_202008171204', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kata-ksm-throttler-1.7.3-1.0.5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kata-proxy-1.7.3-1.0.5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kata-runtime-1.7.3-1.0.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kata-shim-1.7.3-1.0.5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kubeadm-1.17.9-1.0.5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kubectl-1.17.9-1.0.5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kubelet-1.17.9-1.0.5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kubernetes-cni-0.7.1-1.0.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kubernetes-cni-plugins-0.8.6-1.0.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kubernetes-dashboard-2.0.0-1.0.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-agent-1.1.5-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-api-server-1.1.5-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-istio-chart-1.1.5-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-nginx-1.1.5-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-prometheus-chart-1.1.5-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-utils-1.1.5-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcnectl-1.1.5-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'prometheus-2.13.1-1.0.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yq-2.4.0-1.0.5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'conmon / coredns / cri-o / etc');
}
