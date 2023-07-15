#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:2261.
##

include('compat.inc');

if (description)
{
  script_id(175612);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id(
    "CVE-2022-2795",
    "CVE-2022-3094",
    "CVE-2022-3736",
    "CVE-2022-3924"
  );
  script_xref(name:"ALSA", value:"2023:2261");
  script_xref(name:"IAVA", value:"2022-A-0387-S");
  script_xref(name:"IAVA", value:"2023-A-0058-S");

  script_name(english:"AlmaLinux 9 : bind (ALSA-2023:2261)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:2261 advisory.

  - By flooding the target resolver with queries exploiting this flaw an attacker can significantly impair the
    resolver's performance, effectively denying legitimate clients access to the DNS resolution service.
    (CVE-2022-2795)

  - Sending a flood of dynamic DNS updates may cause `named` to allocate large amounts of memory. This, in
    turn, may cause `named` to exit due to a lack of free memory. We are not aware of any cases where this has
    been exploited. Memory is allocated prior to the checking of access permissions (ACLs) and is retained
    during the processing of a dynamic update from a client whose access credentials are accepted. Memory
    allocated to clients that are not permitted to send updates is released immediately upon rejection. The
    scope of this vulnerability is limited therefore to trusted clients who are permitted to make dynamic zone
    changes. If a dynamic update is REFUSED, memory will be released again very quickly. Therefore it is only
    likely to be possible to degrade or stop `named` by sending a flood of unaccepted dynamic updates
    comparable in magnitude to a query flood intended to achieve the same detrimental outcome. BIND 9.11 and
    earlier branches are also affected, but through exhaustion of internal resources rather than memory
    constraints. This may reduce performance but should not be a significant problem for most servers.
    Therefore we don't intend to address this for BIND versions prior to BIND 9.16. This issue affects BIND 9
    versions 9.16.0 through 9.16.36, 9.18.0 through 9.18.10, 9.19.0 through 9.19.8, and 9.16.8-S1 through
    9.16.36-S1. (CVE-2022-3094)

  - BIND 9 resolver can crash when stale cache and stale answers are enabled, option `stale-answer-client-
    timeout` is set to a positive integer, and the resolver receives an RRSIG query. This issue affects BIND 9
    versions 9.16.12 through 9.16.36, 9.18.0 through 9.18.10, 9.19.0 through 9.19.8, and 9.16.12-S1 through
    9.16.36-S1. (CVE-2022-3736)

  - This issue can affect BIND 9 resolvers with `stale-answer-enable yes;` that also make use of the option
    `stale-answer-client-timeout`, configured with a value greater than zero. If the resolver receives many
    queries that require recursion, there will be a corresponding increase in the number of clients that are
    waiting for recursion to complete. If there are sufficient clients already waiting when a new client query
    is received so that it is necessary to SERVFAIL the longest waiting client (see BIND 9 ARM `recursive-
    clients` limit and soft quota), then it is possible for a race to occur between providing a stale answer
    to this older client and sending an early timeout SERVFAIL, which may cause an assertion failure. This
    issue affects BIND 9 versions 9.16.12 through 9.16.36, 9.18.0 through 9.18.10, 9.19.0 through 9.19.8, and
    9.16.12-S1 through 9.16.36-S1. (CVE-2022-3924)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2023-2261.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3924");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-dnssec-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-dnssec-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'bind-9.16.23-11.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-chroot-9.16.23-11.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-devel-9.16.23-11.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-dnssec-doc-9.16.23-11.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-dnssec-utils-9.16.23-11.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-doc-9.16.23-11.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-libs-9.16.23-11.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-license-9.16.23-11.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-utils-9.16.23-11.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'python3-bind-9.16.23-11.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind / bind-chroot / bind-devel / bind-dnssec-doc / bind-dnssec-utils / etc');
}
