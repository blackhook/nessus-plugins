##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-9362.
##

include('compat.inc');

if (description)
{
  script_id(160858);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/09");

  script_cve_id("CVE-2022-24726", "CVE-2022-24921");
  script_xref(name:"IAVB", value:"2022-B-0011-S");

  script_name(english:"Oracle Linux 7 / 8 : olcne / istio / istio (ELSA-2022-9362)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2022-9362 advisory.

  - Istio is an open platform to connect, manage, and secure microservices. In affected versions the Istio
    control plane, istiod, is vulnerable to a request processing error, allowing a malicious attacker that
    sends a specially crafted message which results in the control plane crashing when the validating webhook
    for a cluster is exposed publicly. This endpoint is served over TLS port 15017, but does not require any
    authentication from the attacker. For simple installations, Istiod is typically only reachable from within
    the cluster, limiting the blast radius. However, for some deployments, especially [external
    istiod](https://istio.io/latest/docs/setup/install/external-controlplane/) topologies, this port is
    exposed over the public internet. This issue has been patched in versions 1.13.2, 1.12.5 and 1.11.8. Users
    are advised to upgrade. Users unable to upgrade should disable access to a validating webhook that is
    exposed to the public internet or restrict the set of IP addresses that can query it to a set of known,
    trusted entities. (CVE-2022-24726)

  - regexp.Compile in Go before 1.16.15 and 1.17.x before 1.17.8 allows stack exhaustion via a deeply nested
    expression. (CVE-2022-24921)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-9362.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24921");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:istio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:istio-istioctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-api-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-gluster-chart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-grafana-chart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-istio-chart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-oci-csi-chart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-olm-chart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-prometheus-chart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcnectl");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(7|8)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7 / 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'istio-1.12.6-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'istio-1.12.6'},
    {'reference':'istio-1.13.2-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'istio-1.13.2'},
    {'reference':'istio-istioctl-1.12.6-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'istio-istioctl-1.12.6'},
    {'reference':'istio-istioctl-1.13.2-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'istio-istioctl-1.13.2'},
    {'reference':'olcne-agent-1.4.3-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-api-server-1.4.3-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-gluster-chart-1.4.3-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-grafana-chart-1.4.3-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-istio-chart-1.4.3-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-nginx-1.4.3-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-oci-csi-chart-1.4.3-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-olm-chart-1.4.3-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-prometheus-chart-1.4.3-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-utils-1.4.3-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcnectl-1.4.3-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'istio-1.12.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'istio-1.12.6'},
    {'reference':'istio-1.13.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'istio-1.13.2'},
    {'reference':'istio-istioctl-1.12.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'istio-istioctl-1.12.6'},
    {'reference':'istio-istioctl-1.13.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'istio-istioctl-1.13.2'},
    {'reference':'olcne-agent-1.4.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-api-server-1.4.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-gluster-chart-1.4.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-grafana-chart-1.4.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-istio-chart-1.4.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-nginx-1.4.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-oci-csi-chart-1.4.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-olm-chart-1.4.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-prometheus-chart-1.4.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-utils-1.4.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcnectl-1.4.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'istio / istio-istioctl / olcne-agent / etc');
}
