#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-0824.
##

include('compat.inc');

if (description)
{
  script_id(171676);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/17");

  script_cve_id(
    "CVE-2023-0616",
    "CVE-2023-0767",
    "CVE-2023-25728",
    "CVE-2023-25729",
    "CVE-2023-25730",
    "CVE-2023-25732",
    "CVE-2023-25735",
    "CVE-2023-25737",
    "CVE-2023-25739",
    "CVE-2023-25742",
    "CVE-2023-25743",
    "CVE-2023-25744",
    "CVE-2023-25746"
  );
  script_xref(name:"IAVA", value:"2023-A-0106-S");

  script_name(english:"Oracle Linux 9 : thunderbird (ELSA-2023-0824)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has a package installed that is affected by multiple vulnerabilities as referenced in the
ELSA-2023-0824 advisory.

  - When encoding data from an <code>inputStream</code> in <code>xpcom</code> the size of the input being
    encoded was not correctly calculated potentially leading to an out of bounds memory write.
    (CVE-2023-25732)

  - Mozilla: Content security policy leak in violation reports using iframes (CVE-2023-25728)

  - An invalid downcast from <code>nsTextNode</code> to <code>SVGElement</code> could have lead to undefined
    behavior.  (CVE-2023-25737)

  - When importing a SPKI RSA public key as ECDSA P-256, the key would be handled incorrectly causing the tab
    to crash.  (CVE-2023-25742)

  - Mozilla: Fullscreen notification not shown in Firefox Focus (CVE-2023-25743)

  - Module load requests that failed were not being checked as to whether or not they were cancelled causing a
    use-after-free in <code>ScriptLoadContext</code>.  (CVE-2023-25739)

  - An attacker could construct a PKCS 12 cert bundle in such a way that could allow for arbitrary memory
    writes via PKCS 12 Safe Bag attributes being mishandled.  (CVE-2023-0767)

  - Permission prompts for opening external schemes were only shown for <code>ContentPrincipals</code>
    resulting in extensions being able to open them without user interaction via
    <code>ExpandedPrincipals</code>. This could lead to further malicious actions such as downloading files or
    interacting with software already installed on the system.  (CVE-2023-25729)

  - Mozilla developers Philipp and Gabriele Svelto reported memory safety bugs present in Thunderbird 102.7.
    Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of
    these could have been exploited to run arbitrary code.  (CVE-2023-25746)

  - A background script invoking <code>requestFullscreen</code> and then blocking the main thread could force
    the browser into fullscreen mode indefinitely, resulting in potential user confusion or spoofing attacks.
    (CVE-2023-25730)

  - Mozilla: User Interface lockup with messages combining S/MIME and OpenPGP (CVE-2023-0616)

  - Cross-compartment wrappers wrapping a scripted proxy could have caused objects from other compartments to
    be stored in the main compartment resulting in a use-after-free after unwrapping the proxy.
    (CVE-2023-25735)

  - Mozilla developers Kershaw Chang and the Mozilla Fuzzing Team reported memory safety bugs present in
    Firefox 109 and Firefox ESR 102.7. Some of these bugs showed evidence of memory corruption and we presume
    that with enough effort some of these could have been exploited to run arbitrary code.  (CVE-2023-25744)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-0824.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected thunderbird package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25746");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'thunderbird-102.8.0-2.0.1.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-102.8.0-2.0.1.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird');
}
