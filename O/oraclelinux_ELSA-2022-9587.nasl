##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-9587.
##

include('compat.inc');

if (description)
{
  script_id(163013);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/12");

  script_cve_id(
    "CVE-2022-29224",
    "CVE-2022-29225",
    "CVE-2022-29226",
    "CVE-2022-29227",
    "CVE-2022-29228",
    "CVE-2022-31045"
  );

  script_name(english:"Oracle Linux 7 : olcne (ELSA-2022-9587)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-9587 advisory.

  - Istio is an open platform to connect, manage, and secure microservices. In affected versions ill-formed
    headers sent to Envoy in certain configurations can lead to unexpected memory access resulting in
    undefined behavior or crashing. Users are most likely at risk if they have an Istio ingress Gateway
    exposed to external traffic. This vulnerability has been resolved in versions 1.12.8, 1.13.5, and 1.14.1.
    Users are advised to upgrade. There are no known workarounds for this issue. (CVE-2022-31045)

  - Envoy is a cloud-native high-performance proxy. In versions prior to 1.22.1 secompressors accumulate
    decompressed data into an intermediate buffer before overwriting the body in the decode/encodeBody. This
    may allow an attacker to zip bomb the decompressor by sending a small highly compressed payload.
    Maliciously constructed zip files may exhaust system memory and cause a denial of service. Users are
    advised to upgrade. Users unable to upgrade may consider disabling decompression. (CVE-2022-29225)

  - Envoy is a cloud-native high-performance proxy. Versions of envoy prior to 1.22.1 are subject to a
    segmentation fault in the GrpcHealthCheckerImpl. Envoy can perform various types of upstream health
    checking. One of them uses gRPC. Envoy also has a feature which can hold? (prevent removal) upstream
    hosts obtained via service discovery until configured active health checking fails. If an attacker
    controls an upstream host and also controls service discovery of that host (via DNS, the EDS API, etc.),
    an attacker can crash Envoy by forcing removal of the host from service discovery, and then failing the
    gRPC health check request. This will crash Envoy via a null pointer dereference. Users are advised to
    upgrade to resolve this vulnerability. Users unable to upgrade may disable gRPC health checking and/or
    replace it with a different health checking type as a mitigation. (CVE-2022-29224)

  - Envoy is a cloud-native high-performance proxy. In versions prior to 1.22.1 the OAuth filter would try to
    invoke the remaining filters in the chain after emitting a local response, which triggers an ASSERT() in
    newer versions and corrupts memory on earlier versions. continueDecoding() shouldnt ever be called from
    filters after a local reply has been sent. Users are advised to upgrade. There are no known workarounds
    for this issue. (CVE-2022-29228)

  - Envoy is a cloud-native high-performance edge/middle/service proxy. In versions prior to 1.22.1 if Envoy
    attempts to send an internal redirect of an HTTP request consisting of more than HTTP headers, theres a
    lifetime bug which can be triggered. If while replaying the request Envoy sends a local reply when the
    redirect headers are processed, the downstream state indicates that the downstream stream is not complete.
    On sending the local reply, Envoy will attempt to reset the upstream stream, but as it is actually
    complete, and deleted, this result in a use-after-free. Users are advised to upgrade. Users unable to
    upgrade are advised to disable internal redirects if crashes are observed. (CVE-2022-29227)

  - Envoy is a cloud-native high-performance proxy. In versions prior to 1.22.1 the OAuth filter
    implementation does not include a mechanism for validating access tokens, so by design when the HMAC
    signed cookie is missing a full authentication flow should be triggered. However, the current
    implementation assumes that access tokens are always validated thus allowing access in the presence of any
    access token attached to the request. Users are advised to upgrade. There is no known workaround for this
    issue. (CVE-2022-29226)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-9587.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31045");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'istio-1.13.5-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'istio-istioctl-1.13.5-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-agent-1.4.6-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-api-server-1.4.6-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-gluster-chart-1.4.6-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-grafana-chart-1.4.6-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-istio-chart-1.4.6-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-nginx-1.4.6-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-oci-csi-chart-1.4.6-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-olm-chart-1.4.6-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-prometheus-chart-1.4.6-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-utils-1.4.6-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcnectl-1.4.6-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
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
