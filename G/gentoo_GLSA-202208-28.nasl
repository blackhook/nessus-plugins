#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-28.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164109);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/15");

  script_cve_id(
    "CVE-2021-29509",
    "CVE-2021-41136",
    "CVE-2022-23634",
    "CVE-2022-24790"
  );

  script_name(english:"GLSA-202208-28 : Puma: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-28 (Puma: Multiple Vulnerabilities)

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
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-28");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=794034");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=817893");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=833155");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=836431");
  script_set_attribute(attribute:"solution", value:
"All Puma users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-servers/puma-5.6.4");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24790");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:puma");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "www-servers/puma",
    'unaffected' : make_list("ge 5.6.4"),
    'vulnerable' : make_list("lt 5.6.4")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Puma");
}
