#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-9546.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155011);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/10");

  script_cve_id(
    "CVE-2021-25741",
    "CVE-2021-32777",
    "CVE-2021-32778",
    "CVE-2021-32779",
    "CVE-2021-32780",
    "CVE-2021-32781"
  );

  script_name(english:"Oracle Linux 8 : olcne / istio / istio / kubernetes (ELSA-2021-9546)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-9546 advisory.

  - Envoy is an open source L7 proxy and communication bus designed for large modern service oriented
    architectures. In affected versions when ext-authz extension is sending request headers to the external
    authorization service it must merge multiple value headers according to the HTTP spec. However, only the
    last header value is sent. This may allow specifically crafted requests to bypass authorization. Attackers
    may be able to escalate privileges when using ext-authz extension or back end service that uses multiple
    value headers for authorization. A specifically constructed request may be delivered by an untrusted
    downstream peer in the presence of ext-authz extension. Envoy versions 1.19.1, 1.18.4, 1.17.4, 1.16.5
    contain fixes to the ext-authz extension to correctly merge multiple request header values, when sending
    request for authorization. (CVE-2021-32777)

  - Envoy is an open source L7 proxy and communication bus designed for large modern service oriented
    architectures. In affected versions Envoy transitions a H/2 connection to the CLOSED state when it
    receives a GOAWAY frame without any streams outstanding. The connection state is transitioned to DRAINING
    when it receives a SETTING frame with the SETTINGS_MAX_CONCURRENT_STREAMS parameter set to 0. Receiving
    these two frames in the same I/O event results in abnormal termination of the Envoy process due to invalid
    state transition from CLOSED to DRAINING. A sequence of H/2 frames delivered by an untrusted upstream
    server will result in Denial of Service in the presence of untrusted **upstream** servers. Envoy versions
    1.19.1, 1.18.4 contain fixes to stop processing of pending H/2 frames after connection transition to the
    CLOSED state. (CVE-2021-32780)

  - Envoy is an open source L7 proxy and communication bus designed for large modern service oriented
    architectures. In affected versions after Envoy sends a locally generated response it must stop further
    processing of request or response data. However when local response is generated due the internal buffer
    overflow while request or response is processed by the filter chain the operation may not be stopped
    completely and result in accessing a freed memory block. A specifically constructed request delivered by
    an untrusted downstream or upstream peer in the presence of extensions that modify and increase the size
    of request or response bodies resulting in a Denial of Service when using extensions that modify and
    increase the size of request or response bodies, such as decompressor filter. Envoy versions 1.19.1,
    1.18.4, 1.17.4, 1.16.5 contain fixes to address incomplete termination of request processing after locally
    generated response. As a workaround disable Envoy's decompressor, json-transcoder or grpc-web extensions
    or proprietary extensions that modify and increase the size of request or response bodies, if feasible.
    (CVE-2021-32781)

  - Envoy is an open source L7 proxy and communication bus designed for large modern service oriented
    architectures. In affected versions envoy incorrectly handled a URI '#fragment' element as part of the
    path element. Envoy is configured with an RBAC filter for authorization or similar mechanism with an
    explicit case of a final /admin path element, or is using a negative assertion with final path element
    of /admin. The client sends request to /app1/admin#foo. In Envoy prior to 1.18.0, or 1.18.0+
    configured with path_normalization=false. Envoy treats fragment as a suffix of the query string when
    present, or as a suffix of the path when query string is absent, so it evaluates the final path element as
    /admin#foo and mismatches with the configured /admin path element. In Envoy 1.18.0+ configured with
    path_normalization=true. Envoy transforms this to /app1/admin%23foo and mismatches with the configured
    /admin prefix. The resulting URI is sent to the next server-agent with the offending #foo fragment which
    violates RFC3986 or with the nonsensical %23foo text appended. A specifically constructed request with
    URI containing '#fragment' element delivered by an untrusted client in the presence of path based request
    authorization resulting in escalation of Privileges when path based request authorization extensions.
    Envoy versions 1.19.1, 1.18.4, 1.17.4, 1.16.5 contain fixes that removes fragment from URI path in
    incoming requests. (CVE-2021-32779)

  - A security issue was discovered in Kubernetes where a user may be able to create a container with subpath
    volume mounts to access files & directories outside of the volume, including on the host filesystem.
    (CVE-2021-25741)

  - Envoy is an open source L7 proxy and communication bus designed for large modern service oriented
    architectures. In affected versions envoy's procedure for resetting a HTTP/2 stream has O(N^2) complexity,
    leading to high CPU utilization when a large number of streams are reset. Deployments are susceptible to
    Denial of Service when Envoy is configured with high limit on H/2 concurrent streams. An attacker wishing
    to exploit this vulnerability would require a client opening and closing a large number of H/2 streams.
    Envoy versions 1.19.1, 1.18.4, 1.17.4, 1.16.5 contain fixes to reduce time complexity of resetting HTTP/2
    streams. As a workaround users may limit the number of simultaneous HTTP/2 dreams for upstream and
    downstream peers to a low number, i.e. 100. (CVE-2021-32778)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-9546.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32779");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:istio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:istio-istioctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kubeadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kubectl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kubelet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-api-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-grafana-chart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-istio-chart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-olm-chart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-prometheus-chart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcnectl");
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
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'istio-1.10.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'istio-1.10.4'},
    {'reference':'istio-1.9.8-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'istio-1.9.8'},
    {'reference':'istio-istioctl-1.10.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'istio-istioctl-1.10.4'},
    {'reference':'istio-istioctl-1.9.8-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'istio-istioctl-1.9.8'},
    {'reference':'kubeadm-1.20.11-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kubectl-1.20.11-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kubelet-1.20.11-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-agent-1.3.2-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-api-server-1.3.2-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-grafana-chart-1.3.2-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-istio-chart-1.3.2-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-nginx-1.3.2-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-olm-chart-1.3.2-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-prometheus-chart-1.3.2-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcne-utils-1.3.2-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'olcnectl-1.3.2-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'istio / istio-istioctl / kubeadm / etc');
}
