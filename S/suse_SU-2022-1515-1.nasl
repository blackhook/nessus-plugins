##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1515-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(160523);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2021-29509", "CVE-2021-41136", "CVE-2022-23634");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1515-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : rubygem-puma (SUSE-SU-2022:1515-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2022:1515-1 advisory.

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188527");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196222");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-May/010927.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f6fde7c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41136");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23634");
  script_set_attribute(attribute:"solution", value:
"Update the affected ruby2.5-rubygem-puma and / or ruby2.5-rubygem-puma-doc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23634");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.5-rubygem-puma");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.3|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2/3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'ruby2.5-rubygem-puma-4.3.11-150000.3.6.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ruby2.5-rubygem-puma-doc-4.3.11-150000.3.6.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ruby2.5-rubygem-puma-4.3.11-150000.3.6.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ruby2.5-rubygem-puma-doc-4.3.11-150000.3.6.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ruby2.5-rubygem-puma-4.3.11-150000.3.6.2', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15']},
    {'reference':'ruby2.5-rubygem-puma-4.3.11-150000.3.6.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'ruby2.5-rubygem-puma-4.3.11-150000.3.6.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'ruby2.5-rubygem-puma-4.3.11-150000.3.6.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby2.5-rubygem-puma / ruby2.5-rubygem-puma-doc');
}
