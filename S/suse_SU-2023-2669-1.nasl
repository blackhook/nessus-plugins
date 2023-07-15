#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2669-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(177719);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id(
    "CVE-2022-25881",
    "CVE-2023-30581",
    "CVE-2023-30585",
    "CVE-2023-30588",
    "CVE-2023-30589",
    "CVE-2023-30590",
    "CVE-2023-31124",
    "CVE-2023-31130",
    "CVE-2023-31147",
    "CVE-2023-32067"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2669-1");
  script_xref(name:"IAVB", value:"2023-B-0042");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : nodejs18 (SUSE-SU-2023:2669-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:2669-1 advisory.

  - This affects versions of the package http-cache-semantics before 4.1.1. The issue can be exploited via
    malicious request header values sent to a server, when that server reads the cache policy from the request
    using this library. (CVE-2022-25881)

  - c-ares is an asynchronous resolver library. When cross-compiling c-ares and using the autotools build
    system, CARES_RANDOM_FILE will not be set, as seen when cross compiling aarch64 android. This will
    downgrade to using rand() as a fallback which could allow an attacker to take advantage of the lack of
    entropy by not using a CSPRNG. This issue was patched in version 1.19.1. (CVE-2023-31124)

  - c-ares is an asynchronous resolver library. ares_inet_net_pton() is vulnerable to a buffer underflow for
    certain ipv6 addresses, in particular 0::00:00:00/2 was found to cause an issue. C-ares only uses this
    function internally for configuration purposes which would require an administrator to configure such an
    address via ares_set_sortlist(). However, users may externally use ares_inet_net_pton() for other purposes
    and thus be vulnerable to more severe issues. This issue has been fixed in 1.19.1. (CVE-2023-31130)

  - c-ares is an asynchronous resolver library. When /dev/urandom or RtlGenRandom() are unavailable, c-ares
    uses rand() to generate random numbers used for DNS query ids. This is not a CSPRNG, and it is also not
    seeded by srand() so will generate predictable output. Input from the random number generator is fed into
    a non-compilant RC4 implementation and may not be as strong as the original RC4 implementation. No attempt
    is made to look for modern OS-provided CSPRNGs like arc4random() that is widely available. This issue has
    been fixed in version 1.19.1. (CVE-2023-31147)

  - c-ares is an asynchronous resolver library. c-ares is vulnerable to denial of service. If a target
    resolver sends a query, the attacker forges a malformed UDP packet with a length of 0 and returns them to
    the target resolver. The target resolver erroneously interprets the 0 length as a graceful shutdown of the
    connection. This issue has been patched in version 1.19.1. (CVE-2023-32067)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-25881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-30581");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-30585");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-30588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-30589");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-30590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-31124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-31130");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-31147");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-32067");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-June/015346.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9dcf9044");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-31147");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs18-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs18-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:npm18");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.4|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'nodejs18-18.16.1-150400.9.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-web-scripting-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'nodejs18-devel-18.16.1-150400.9.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-web-scripting-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'nodejs18-docs-18.16.1-150400.9.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-web-scripting-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'npm18-18.16.1-150400.9.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-web-scripting-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'nodejs18-18.16.1-150400.9.9.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'nodejs18-devel-18.16.1-150400.9.9.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'nodejs18-docs-18.16.1-150400.9.9.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'npm18-18.16.1-150400.9.9.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'corepack18-18.16.1-150400.9.9.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'nodejs18-18.16.1-150400.9.9.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'nodejs18-devel-18.16.1-150400.9.9.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'nodejs18-docs-18.16.1-150400.9.9.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'npm18-18.16.1-150400.9.9.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'corepack18-18.16.1-150400.9.9.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'nodejs18-18.16.1-150400.9.9.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'nodejs18-devel-18.16.1-150400.9.9.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'nodejs18-docs-18.16.1-150400.9.9.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'npm18-18.16.1-150400.9.9.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'corepack18 / nodejs18 / nodejs18-devel / nodejs18-docs / npm18');
}
