#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-051.
##

include('compat.inc');

if (description)
{
  script_id(164760);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/06");

  script_cve_id(
    "CVE-2021-29509",
    "CVE-2021-41136",
    "CVE-2022-23634",
    "CVE-2022-24790"
  );

  script_name(english:"Amazon Linux 2022 :  (ALAS2022-2022-051)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2022-2022-051 advisory.

  - Puma is a concurrent HTTP 1.1 server for Ruby/Rack applications. The fix for CVE-2019-16770 was
    incomplete. The original fix only protected existing connections that had already been accepted from
    having their requests starved by greedy persistent-connections saturating all threads in the same process.
    However, new connections may still be starved by greedy persistent-connections saturating all threads in
    all processes in the cluster. A `puma` server which received more concurrent `keep-alive` connections than
    the server had threads in its threadpool would service only a subset of connections, denying service to
    the unserved connections. This problem has been fixed in `puma` 4.3.8 and 5.3.1. Setting `queue_requests
    false` also fixes the issue. This is not advised when using `puma` without a reverse proxy, such as
    `nginx` or `apache`, because you will open yourself to slow client attacks (e.g. slowloris). The fix is
    very small and a git patch is available for those using unsupported versions of Puma. (CVE-2021-29509)

  - Puma is a HTTP 1.1 server for Ruby/Rack applications. Prior to versions 5.5.1 and 4.3.9, using `puma` with
    a proxy which forwards HTTP header values which contain the LF character could allow HTTP request
    smugggling. A client could smuggle a request through a proxy, causing the proxy to send a response back to
    another unknown client. The only proxy which has this behavior, as far as the Puma team is aware of, is
    Apache Traffic Server. If the proxy uses persistent connections and the client adds another request in via
    HTTP pipelining, the proxy may mistake it as the first request's body. Puma, however, would see it as two
    requests, and when processing the second request, send back a response that the proxy does not expect. If
    the proxy has reused the persistent connection to Puma to send another request for a different client, the
    second response from the first client will be sent to the second client. This vulnerability was patched in
    Puma 5.5.1 and 4.3.9. As a workaround, do not use Apache Traffic Server with `puma`. (CVE-2021-41136)

  - Puma is a Ruby/Rack web server built for parallelism. Prior to `puma` version `5.6.2`, `puma` may not
    always call `close` on the response body. Rails, prior to version `7.0.2.2`, depended on the response body
    being closed in order for its `CurrentAttributes` implementation to work correctly. The combination of
    these two behaviors (Puma not closing the body + Rails' Executor implementation) causes information
    leakage. This problem is fixed in Puma versions 5.6.2 and 4.3.11. This problem is fixed in Rails versions
    7.02.2, 6.1.4.6, 6.0.4.6, and 5.2.6.2. Upgrading to a patched Rails _or_ Puma version fixes the
    vulnerability. (CVE-2022-23634)

  - Puma is a simple, fast, multi-threaded, parallel HTTP 1.1 server for Ruby/Rack applications. When using
    Puma behind a proxy that does not properly validate that the incoming HTTP request matches the RFC7230
    standard, Puma and the frontend proxy may disagree on where a request starts and ends. This would allow
    requests to be smuggled via the front-end proxy to Puma. The vulnerability has been fixed in 5.6.4 and
    4.3.12. Users are advised to upgrade as soon as possible. Workaround: when deploying a proxy in front of
    Puma, turning on any and all functionality to make sure that the request matches the RFC7230 standard.
    (CVE-2022-24790)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-051.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-29509.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-41136.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-23634.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-24790.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update --releasever=2022.0.20220419 rubygem-puma' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24790");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-puma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-puma-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-puma-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-puma-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "-2022")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2022", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'rubygem-puma-4.3.12-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-puma-4.3.12-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-puma-4.3.12-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-puma-debuginfo-4.3.12-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-puma-debuginfo-4.3.12-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-puma-debuginfo-4.3.12-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-puma-debugsource-4.3.12-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-puma-debugsource-4.3.12-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-puma-debugsource-4.3.12-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-puma-doc-4.3.12-1.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rubygem-puma / rubygem-puma-debuginfo / rubygem-puma-debugsource / etc");
}