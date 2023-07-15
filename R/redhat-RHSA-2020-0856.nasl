##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0856. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(134669);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/13");

  script_cve_id(
    "CVE-2020-2583",
    "CVE-2020-2593",
    "CVE-2020-2604",
    "CVE-2020-2659"
  );
  script_xref(name:"RHSA", value:"2020:0856");

  script_name(english:"RHEL 6 : java-1.8.0-ibm (RHSA-2020:0856)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:0856 advisory.

  - OpenJDK: Incorrect exception processing during deserialization in BeanContextSupport (Serialization,
    8224909) (CVE-2020-2583)

  - OpenJDK: Incorrect isBuiltinStreamHandler check causing URL normalization issues (Networking, 8228548)
    (CVE-2020-2593)

  - OpenJDK: Serialization filter changes via jdk.serialFilter property modification (Serialization, 8231422)
    (CVE-2020-2604)

  - OpenJDK: Incomplete enforcement of maxDatagramSockets limit in DatagramChannelImpl (Networking, 8231795)
    (CVE-2020-2659)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/172.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/471.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/770.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2583");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2593");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2604");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2659");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1790444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1790884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1790944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1791284");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.8.0-ibm and / or java-1.8.0-ibm-devel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(172, 471, 770);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-devel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Red Hat' >!< release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
var os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var pkgs = [
    {'reference':'java-1.8.0-ibm-1.8.0.6.5-1jpp.1.el6_10', 'cpu':'s390x', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-5'},
    {'reference':'java-1.8.0-ibm-1.8.0.6.5-1jpp.1.el6_10', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-5'},
    {'reference':'java-1.8.0-ibm-devel-1.8.0.6.5-1jpp.1.el6_10', 'cpu':'s390x', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-5'},
    {'reference':'java-1.8.0-ibm-devel-1.8.0.6.5-1jpp.1.el6_10', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-5'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'RHEL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference &&
      release &&
      (!exists_check || rpm_exists(release:release, rpm:exists_check)) &&
      rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
}

if (flag)
{
  var extra = NULL;
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.8.0-ibm / java-1.8.0-ibm-devel');
}
