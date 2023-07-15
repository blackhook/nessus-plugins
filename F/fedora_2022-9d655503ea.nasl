#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-9d655503ea
#

include('compat.inc');

if (description)
{
  script_id(169174);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/29");

  script_cve_id(
    "CVE-2010-5312",
    "CVE-2016-7103",
    "CVE-2021-41182",
    "CVE-2021-41183",
    "CVE-2021-41184",
    "CVE-2022-25271",
    "CVE-2022-25275"
  );
  script_xref(name:"IAVA", value:"2022-A-0090-S");
  script_xref(name:"IAVA", value:"2022-A-0296-S");
  script_xref(name:"FEDORA", value:"2022-9d655503ea");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Fedora 36 : drupal7 (2022-9d655503ea)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 36 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2022-9d655503ea advisory.

  - Cross-site scripting (XSS) vulnerability in jquery.ui.dialog.js in the Dialog widget in jQuery UI before
    1.10.0 allows remote attackers to inject arbitrary web script or HTML via the title option.
    (CVE-2010-5312)

  - Cross-site scripting (XSS) vulnerability in jQuery UI before 1.12.0 might allow remote attackers to inject
    arbitrary web script or HTML via the closeText parameter of the dialog function. (CVE-2016-7103)

  - jQuery-UI is the official jQuery user interface library. Prior to version 1.13.0, accepting the value of
    the `altField` option of the Datepicker widget from untrusted sources may execute untrusted code. The
    issue is fixed in jQuery UI 1.13.0. Any string value passed to the `altField` option is now treated as a
    CSS selector. A workaround is to not accept the value of the `altField` option from untrusted sources.
    (CVE-2021-41182)

  - jQuery-UI is the official jQuery user interface library. Prior to version 1.13.0, accepting the value of
    various `*Text` options of the Datepicker widget from untrusted sources may execute untrusted code. The
    issue is fixed in jQuery UI 1.13.0. The values passed to various `*Text` options are now always treated as
    pure text, not HTML. A workaround is to not accept the value of the `*Text` options from untrusted
    sources. (CVE-2021-41183)

  - jQuery-UI is the official jQuery user interface library. Prior to version 1.13.0, accepting the value of
    the `of` option of the `.position()` util from untrusted sources may execute untrusted code. The issue is
    fixed in jQuery UI 1.13.0. Any string value passed to the `of` option is now treated as a CSS selector. A
    workaround is to not accept the value of the `of` option from untrusted sources. (CVE-2021-41184)

  - Drupal core's form API has a vulnerability where certain contributed or custom modules' forms may be
    vulnerable to improper input validation. This could allow an attacker to inject disallowed values or
    overwrite data. Affected forms are uncommon, but in certain cases an attacker could alter critical or
    sensitive data. (CVE-2022-25271)

  - In some situations, the Image module does not correctly check access to image files not stored in the
    standard public files directory when generating derivative images using the image styles system. Access to
    a non-public file is checked only if it is stored in the private file system. However, some contributed
    modules provide additional file systems, or schemes, which may lead to this vulnerability. This
    vulnerability is mitigated by the fact that it only applies when the site sets (Drupal 9)
    $config['image.settings']['allow_insecure_derivatives'] or (Drupal 7)
    $conf['image_allow_insecure_derivatives'] to TRUE. The recommended and default setting is FALSE, and
    Drupal core does not provide a way to change that in the admin UI. Some sites may require configuration
    changes following this security release. Review the release notes for your Drupal version if you have
    issues accessing files or image styles after updating. (CVE-2022-25275)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-9d655503ea");
  script_set_attribute(attribute:"solution", value:
"Update the affected drupal7 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25271");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^36([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 36', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'drupal7-7.92-1.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'drupal7');
}
