#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2224-2. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(177484);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/22");

  script_cve_id(
    "CVE-2023-28319",
    "CVE-2023-28320",
    "CVE-2023-28321",
    "CVE-2023-28322"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2224-2");
  script_xref(name:"IAVA", value:"2023-A-0259");

  script_name(english:"openSUSE 15 Security Update : curl (SUSE-SU-2023:2224-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
SUSE-SU-2023:2224-2 advisory.

  - A use after free vulnerability exists in curl <v8.1.0 in the way libcurl offers a feature to verify an SSH
    server's public key using a SHA 256 hash. When this check fails, libcurl would free the memory for the
    fingerprint before it returns an error message containing the (now freed) hash. This flaw risks inserting
    sensitive heap-based data into the error message that might be shown to users or otherwise get leaked and
    revealed. (CVE-2023-28319)

  - A denial of service vulnerability exists in curl <v8.1.0 in the way libcurl provides several different
    backends for resolving host names, selected at build time. If it is built to use the synchronous resolver,
    it allows name resolves to time-out slow operations using `alarm()` and `siglongjmp()`. When doing this,
    libcurl used a global buffer that was not mutex protected and a multi-threaded application might therefore
    crash or otherwise misbehave. (CVE-2023-28320)

  - An improper certificate validation vulnerability exists in curl <v8.1.0 in the way it supports matching of
    wildcard patterns when listed as Subject Alternative Name in TLS server certificates. curl can be built
    to use its own name matching function for TLS rather than one provided by a TLS library. This private
    wildcard matching function would match IDN (International Domain Name) hosts incorrectly and could as a
    result accept patterns that otherwise should mismatch. IDN hostnames are converted to puny code before
    used for certificate checks. Puny coded names always start with `xn--` and should not be allowed to
    pattern match, but the wildcard check in curl could still check for `x*`, which would match even though
    the IDN name most likely contained nothing even resembling an `x`. (CVE-2023-28321)

  - An information disclosure vulnerability exists in curl <v8.1.0 when doing HTTP(S) transfers, libcurl might
    erroneously use the read callback (`CURLOPT_READFUNCTION`) to ask for data to send, even when the
    `CURLOPT_POSTFIELDS` option has been set, if the same handle previously wasused to issue a `PUT` request
    which used that callback. This flaw may surprise the application and cause it to misbehave and either send
    off the wrong data or use memory after free or similar in the second transfer. The problem exists in the
    logic for a reused handle when it is (expected to be) changed from a PUT to a POST. (CVE-2023-28322)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211231");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211232");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211233");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-June/015260.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2062e88c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28319");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28320");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28321");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28322");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28319");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^SUSE") audit(AUDIT_OS_NOT, "openSUSE");
var os_ver = pregmatch(pattern: "^(SUSE[\d.]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'openSUSE 15', 'openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE (' + os_ver + ')', cpu);

var pkgs = [
    {'reference':'curl-8.0.1-150400.5.23.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libcurl-devel-32bit-8.0.1-150400.5.23.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libcurl-devel-8.0.1-150400.5.23.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libcurl4-32bit-8.0.1-150400.5.23.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libcurl4-8.0.1-150400.5.23.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl / libcurl-devel / libcurl-devel-32bit / libcurl4 / etc');
}
