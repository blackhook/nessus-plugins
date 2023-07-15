##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2021-4cebc3aff9
#

include('compat.inc');

if (description)
{
  script_id(146407);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/12");
  script_xref(name:"FEDORA", value:"2021-4cebc3aff9");

  script_name(english:"Fedora 32 : 1:java-1.8.0-openjdk (2021-4cebc3aff9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 32 host has a package installed that is affected by a vulnerability as referenced in the
FEDORA-2021-4cebc3aff9 advisory.

  - # New in release OpenJDK 8u282 (2021-01-19)  Live versions of these release notes can be found at:  *
    https://bitly.com/openjdk8u282 * https://builds.shipilev.net/backports-monitor/release-notes-
    openjdk8u282.txt  ## Security fixes   * JDK-8247619: Improve Direct Buffering of Characters ## Other
    changes   * [JDK-8230839](https://bugs.openjdk.java.net/browse/JDK-8230839): Updated XML Signature
    Implementation to Apache Santuario 2.1.3, adding support for embedding elliptic curve public keys in the
    KeyValue element   * Default to RSA when using keytool, as DSA is only supported by the LEGACY crypto
    policy.   * Make java-1.8.0-openjdk-demo own its directories as well as its files (FEDORA-2021-4cebc3aff9)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2021-4cebc3aff9");
  script_set_attribute(attribute:"solution", value:
"Update the affected 1:java-1.8.0-openjdk package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.8.0-openjdk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Fedora' >!< release) audit(AUDIT_OS_NOT, 'Fedora');
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^32([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 32', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

pkgs = [
    {'reference':'java-1.8.0-openjdk-1.8.0.282.b08-0.fc32', 'release':'FC32', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, '1:java-1.8.0-openjdk');
}
