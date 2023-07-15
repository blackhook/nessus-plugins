#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:7288.
##

include('compat.inc');

if (description)
{
  script_id(166808);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/15");

  script_cve_id("CVE-2022-3602", "CVE-2022-3786");
  script_xref(name:"ALSA", value:"2022:7288");
  script_xref(name:"IAVA", value:"2022-A-0452-S");
  script_xref(name:"CEA-ID", value:"CEA-2022-0036");

  script_name(english:"AlmaLinux 9 : openssl (ALSA-2022:7288)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2022:7288 advisory.

  - A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint
    checking. Note that this occurs after certificate chain signature verification and requires either a CA to
    have signed the malicious certificate or for the application to continue certificate verification despite
    failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to
    overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash
    (causing a denial of service) or potentially remote code execution. Many platforms implement stack
    overflow protections which would mitigate against the risk of remote code execution. The risk may be
    further mitigated based on stack layout for any given platform/compiler. Pre-announcements of
    CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors
    described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new
    version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server.
    In a TLS server, this can be triggered if the server requests client authentication and a malicious client
    connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6). (CVE-2022-3602)

  - A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint
    checking. Note that this occurs after certificate chain signature verification and requires either a CA to
    have signed a malicious certificate or for an application to continue certificate verification despite
    failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a
    certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the
    stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this
    can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server
    requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected
    3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6). (CVE-2022-3786)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2022-7288.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3786");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 121, 193);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'openssl-3.0.1-43.el9_0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-devel-3.0.1-43.el9_0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-libs-3.0.1-43.el9_0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-perl-3.0.1-43.el9_0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssl / openssl-devel / openssl-libs / openssl-perl');
}
