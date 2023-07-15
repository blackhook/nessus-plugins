#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-165.
##

include('compat.inc');

if (description)
{
  script_id(175073);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/04");

  script_cve_id(
    "CVE-2023-27487",
    "CVE-2023-27488",
    "CVE-2023-27491",
    "CVE-2023-27492",
    "CVE-2023-27493",
    "CVE-2023-27496"
  );

  script_name(english:"Amazon Linux 2023 : ecs-service-connect-agent (ALAS2023-2023-165)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-165 advisory.

  - Envoy is an open source edge and service proxy designed for cloud-native applications. Prior to versions
    1.26.0, 1.25.3, 1.24.4, 1.23.6, and 1.22.9, the client may bypass JSON Web Token (JWT) checks and forge
    fake original paths. The header `x-envoy-original-path` should be an internal header, but Envoy does not
    remove this header from the request at the beginning of request processing when it is sent from an
    untrusted client. The faked header would then be used for trace logs and grpc logs, as well as used in the
    URL used for `jwt_authn` checks if the `jwt_authn` filter is used, and any other upstream use of the
    x-envoy-original-path header. Attackers may forge a trusted `x-envoy-original-path` header. Versions
    1.26.0, 1.25.3, 1.24.4, 1.23.6, and 1.22.9 have patches for this issue. (CVE-2023-27487)

  - Envoy is an open source edge and service proxy designed for cloud-native applications. Prior to versions
    1.26.0, 1.25.3, 1.24.4, 1.23.6, and 1.22.9, escalation of privileges is possible when `failure_mode_allow:
    true` is configured for `ext_authz` filter. For affected components that are used for logging and/or
    visibility, requests may not be logged by the receiving service. When Envoy was configured to use
    ext_authz, ext_proc, tap, ratelimit filters, and grpc access log service and an http header with non-UTF-8
    data was received, Envoy would generate an invalid protobuf message and send it to the configured service.
    The receiving service would typically generate an error when decoding the protobuf message. For ext_authz
    that was configured with ``failure_mode_allow: true``, the request would have been allowed in this case.
    For the other services, this could have resulted in other unforeseen errors such as a lack of visibility
    into requests. As of versions 1.26.0, 1.25.3, 1.24.4, 1.23.6, and 1.22.9, Envoy by default sanitizes the
    values sent in gRPC service calls to be valid UTF-8, replacing data that is not valid UTF-8 with a `!`
    character. This behavioral change can be temporarily reverted by setting runtime guard
    `envoy.reloadable_features.service_sanitize_non_utf8_strings` to false. As a workaround, one may set
    `failure_mode_allow: false` for `ext_authz`. (CVE-2023-27488)

  - Envoy is an open source edge and service proxy designed for cloud-native applications. Compliant HTTP/1
    service should reject malformed request lines. Prior to versions 1.26.0, 1.25.3, 1.24.4, 1.23.6, and
    1.22.9, There is a possibility that non compliant HTTP/1 service may allow malformed requests, potentially
    leading to a bypass of security policies. This issue is fixed in versions 1.26.0, 1.25.3, 1.24.4, 1.23.6,
    and 1.22.9. (CVE-2023-27491)

  - Envoy is an open source edge and service proxy designed for cloud-native applications. Prior to versions
    1.26.0, 1.25.3, 1.24.4, 1.23.6, and 1.22.9, the Lua filter is vulnerable to denial of service. Attackers
    can send large request bodies for routes that have Lua filter enabled and trigger crashes. As of versions
    versions 1.26.0, 1.25.3, 1.24.4, 1.23.6, and 1.22.9, Envoy no longer invokes the Lua coroutine if the
    filter has been reset. As a workaround for those whose Lua filter is buffering all requests/ responses,
    mitigate by using the buffer filter to avoid triggering the local reply in the Lua filter.
    (CVE-2023-27492)

  - Envoy is an open source edge and service proxy designed for cloud-native applications. Prior to versions
    1.26.0, 1.25.3, 1.24.4, 1.23.6, and 1.22.9, Envoy does not sanitize or escape request properties when
    generating request headers. This can lead to characters that are illegal in header values to be sent to
    the upstream service. In the worst case, it can cause upstream service to interpret the original request
    as two pipelined requests, possibly bypassing the intent of Envoy's security policy. Versions 1.26.0,
    1.25.3, 1.24.4, 1.23.6, and 1.22.9 contain a patch. As a workaround, disable adding request headers based
    on the downstream request properties, such as downstream certificate properties. (CVE-2023-27493)

  - Envoy is an open source edge and service proxy designed for cloud-native applications. Prior to versions
    1.26.0, 1.25.3, 1.24.4, 1.23.6, and 1.22.9, the OAuth filter assumes that a `state` query param is present
    on any response that looks like an OAuth redirect response. Sending it a request with the URI path
    equivalent to the redirect path, without the `state` parameter, will lead to abnormal termination of Envoy
    process. Versions 1.26.0, 1.25.3, 1.24.4, 1.23.6, and 1.22.9 contain a patch. The issue can also be
    mitigated by locking down OAuth traffic, disabling the filter, or by filtering traffic before it reaches
    the OAuth filter (e.g. via a lua script). (CVE-2023-27496)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-165.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-27487.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-27488.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-27491.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-27492.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-27493.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-27496.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update ecs-service-connect-agent --releasever 2023.0.20230503' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27488");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ecs-service-connect-agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'ecs-service-connect-agent-v1.25.4.0-1.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ecs-service-connect-agent-v1.25.4.0-1.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ecs-service-connect-agent");
}