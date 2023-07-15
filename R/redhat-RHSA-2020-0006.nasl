##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0006. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(132684);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/13");

  script_cve_id(
    "CVE-2019-2945",
    "CVE-2019-2962",
    "CVE-2019-2964",
    "CVE-2019-2973",
    "CVE-2019-2975",
    "CVE-2019-2978",
    "CVE-2019-2981",
    "CVE-2019-2983",
    "CVE-2019-2988",
    "CVE-2019-2989",
    "CVE-2019-2992",
    "CVE-2019-2996",
    "CVE-2019-2999",
    "CVE-2019-17631"
  );
  script_xref(name:"RHSA", value:"2020:0006");
  script_xref(name:"IAVA", value:"2019-A-0385");

  script_name(english:"RHEL 6 : java-1.8.0-ibm (RHSA-2020:0006)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:0006 advisory.

  - IBM JDK: Unrestricted access to diagnostic operations (CVE-2019-17631)

  - OpenJDK: Missing restrictions on use of custom SocketImpl (Networking, 8218573) (CVE-2019-2945)

  - OpenJDK: NULL pointer dereference in DrawGlyphList (2D, 8222690) (CVE-2019-2962)

  - OpenJDK: Unexpected exception thrown by Pattern processing crafted regular expression (Concurrency,
    8222684) (CVE-2019-2964)

  - OpenJDK: Unexpected exception thrown by XPathParser processing crafted XPath expression (JAXP, 8223505)
    (CVE-2019-2973)

  - OpenJDK: Unexpected exception thrown during regular expression processing in Nashorn (Scripting, 8223518)
    (CVE-2019-2975)

  - OpenJDK: Incorrect handling of nested jar: URLs in Jar URL handler (Networking, 8223892) (CVE-2019-2978)

  - OpenJDK: Unexpected exception thrown by XPath processing crafted XPath expression (JAXP, 8224532)
    (CVE-2019-2981)

  - OpenJDK: Unexpected exception thrown during Font object deserialization (Serialization, 8224915)
    (CVE-2019-2983)

  - OpenJDK: Integer overflow in bounds check in SunGraphics2D (2D, 8225292) (CVE-2019-2988)

  - OpenJDK: Incorrect handling of HTTP proxy responses in HttpURLConnection (Networking, 8225298)
    (CVE-2019-2989)

  - OpenJDK: Excessive memory allocation in CMap when reading TrueType font (2D, 8225597) (CVE-2019-2992)

  - Oracle JDK: unspecified vulnerability fixed in 8u221 (Deployment) (CVE-2019-2996)

  - OpenJDK: Insufficient filtering of HTML event attributes in Javadoc (Javadoc, 8226765) (CVE-2019-2999)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/79.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/190.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/248.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/285.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/476.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/770.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2945");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2962");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2964");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2973");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2975");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2978");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2981");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2983");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2988");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2989");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2992");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2996");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2999");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-17631");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760980");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1761006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1761146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1761262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1761266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1761596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1761601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1778942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1779880");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.8.0-ibm and / or java-1.8.0-ibm-devel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17631");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 190, 248, 285, 476, 770);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-devel");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'reference':'java-1.8.0-ibm-1.8.0.6.0-1jpp.1.el6_10', 'cpu':'s390x', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-5'},
    {'reference':'java-1.8.0-ibm-1.8.0.6.0-1jpp.1.el6_10', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-5'},
    {'reference':'java-1.8.0-ibm-devel-1.8.0.6.0-1jpp.1.el6_10', 'cpu':'s390x', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-5'},
    {'reference':'java-1.8.0-ibm-devel-1.8.0.6.0-1jpp.1.el6_10', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-5'}
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
