##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4348 and
# CentOS Errata and Security Advisory 2020:4348 respectively.
##

include('compat.inc');

if (description)
{
  script_id(142646);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-14779",
    "CVE-2020-14781",
    "CVE-2020-14782",
    "CVE-2020-14792",
    "CVE-2020-14796",
    "CVE-2020-14797",
    "CVE-2020-14803"
  );
  script_xref(name:"RHSA", value:"2020:4348");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"CentOS 6 : java-1.8.0-openjdk (CESA-2020:4348)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:4348 advisory.

  - OpenJDK: High memory usage during deserialization of Proxy class with many interfaces (Serialization,
    8236862) (CVE-2020-14779)

  - OpenJDK: Credentials sent over unencrypted LDAP connection (JNDI, 8237990) (CVE-2020-14781)

  - OpenJDK: Certificate blacklist bypass via alternate certificate encodings (Libraries, 8237995)
    (CVE-2020-14782)

  - OpenJDK: Integer overflow leading to out-of-bounds access (Hotspot, 8241114) (CVE-2020-14792)

  - OpenJDK: Missing permission check in path to URI conversion (Libraries, 8242680) (CVE-2020-14796)

  - OpenJDK: Incomplete check for invalid characters in URI to path conversion (Libraries, 8242685)
    (CVE-2020-14797)

  - OpenJDK: Race condition in NIO Buffer boundary checks (Libraries, 8244136) (CVE-2020-14803)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-announce/2020-November/035810.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16474c7b");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/20.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/190.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/295.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/319.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/367.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/770.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14792");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14803");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20, 190, 295, 319, 367, 770);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'CentOS 6.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'java-1.8.0-openjdk-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'i686', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'x86_64', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-debug-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'i686', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-debug-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'x86_64', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-demo-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'i686', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-demo-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'x86_64', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-demo-debug-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'i686', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-demo-debug-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'x86_64', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-devel-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'i686', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-devel-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'x86_64', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-devel-debug-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'i686', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-devel-debug-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'x86_64', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-headless-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'i686', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-headless-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'x86_64', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-headless-debug-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'i686', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-headless-debug-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'x86_64', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-javadoc-1.8.0.272.b10-0.el6_10', 'sp':'10', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-javadoc-debug-1.8.0.272.b10-0.el6_10', 'sp':'10', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-src-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'i686', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-src-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'x86_64', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-src-debug-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'i686', 'release':'CentOS-6'},
    {'reference':'java-1.8.0-openjdk-src-debug-1.8.0.272.b10-0.el6_10', 'sp':'10', 'cpu':'x86_64', 'release':'CentOS-6'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.8.0-openjdk / java-1.8.0-openjdk-debug / java-1.8.0-openjdk-demo / etc');
}
