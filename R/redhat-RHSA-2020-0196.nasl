##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0196. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(133167);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2020-2583",
    "CVE-2020-2590",
    "CVE-2020-2593",
    "CVE-2020-2601",
    "CVE-2020-2604",
    "CVE-2020-2654",
    "CVE-2020-2659"
  );
  script_xref(name:"RHSA", value:"2020:0196");

  script_name(english:"RHEL 7 : java-1.8.0-openjdk (RHSA-2020:0196)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:0196 advisory.

  - OpenJDK: Incorrect exception processing during deserialization in BeanContextSupport (Serialization,
    8224909) (CVE-2020-2583)

  - OpenJDK: Improper checks of SASL message properties in GssKrb5Base (Security, 8226352) (CVE-2020-2590)

  - OpenJDK: Incorrect isBuiltinStreamHandler check causing URL normalization issues (Networking, 8228548)
    (CVE-2020-2593)

  - OpenJDK: Use of unsafe RSA-MD5 checksum in Kerberos TGS (Security, 8229951) (CVE-2020-2601)

  - OpenJDK: Serialization filter changes via jdk.serialFilter property modification (Serialization, 8231422)
    (CVE-2020-2604)

  - OpenJDK: Excessive memory usage in OID processing in X.509 certificate parsing (Libraries, 8234037)
    (CVE-2020-2654)

  - OpenJDK: Incomplete enforcement of maxDatagramSockets limit in DatagramChannelImpl (Networking, 8231795)
    (CVE-2020-2659)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2583");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2590");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2593");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2601");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2604");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2654");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2659");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0196");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1790444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1790556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1790570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1790884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1790944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1791217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1791284");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 172, 327, 471, 770);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:7.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:7.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:7.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:7.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-accessibility-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-javadoc-zip-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/7/7.7/x86_64/debug',
      'content/aus/rhel/server/7/7.7/x86_64/optional/debug',
      'content/aus/rhel/server/7/7.7/x86_64/optional/os',
      'content/aus/rhel/server/7/7.7/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/7/7.7/x86_64/os',
      'content/aus/rhel/server/7/7.7/x86_64/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/debug',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/highavailability/debug',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/highavailability/os',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/optional/debug',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/optional/os',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/optional/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/os',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/sap-hana/debug',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/sap-hana/os',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/sap-hana/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/sap/debug',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/sap/os',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/source/SRPMS',
      'content/e4s/rhel/server/7/7.7/x86_64/debug',
      'content/e4s/rhel/server/7/7.7/x86_64/highavailability/debug',
      'content/e4s/rhel/server/7/7.7/x86_64/highavailability/os',
      'content/e4s/rhel/server/7/7.7/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel/server/7/7.7/x86_64/optional/debug',
      'content/e4s/rhel/server/7/7.7/x86_64/optional/os',
      'content/e4s/rhel/server/7/7.7/x86_64/optional/source/SRPMS',
      'content/e4s/rhel/server/7/7.7/x86_64/os',
      'content/e4s/rhel/server/7/7.7/x86_64/sap-hana/debug',
      'content/e4s/rhel/server/7/7.7/x86_64/sap-hana/os',
      'content/e4s/rhel/server/7/7.7/x86_64/sap-hana/source/SRPMS',
      'content/e4s/rhel/server/7/7.7/x86_64/sap/debug',
      'content/e4s/rhel/server/7/7.7/x86_64/sap/os',
      'content/e4s/rhel/server/7/7.7/x86_64/sap/source/SRPMS',
      'content/e4s/rhel/server/7/7.7/x86_64/source/SRPMS',
      'content/eus/rhel/computenode/7/7.7/x86_64/debug',
      'content/eus/rhel/computenode/7/7.7/x86_64/optional/debug',
      'content/eus/rhel/computenode/7/7.7/x86_64/optional/os',
      'content/eus/rhel/computenode/7/7.7/x86_64/optional/source/SRPMS',
      'content/eus/rhel/computenode/7/7.7/x86_64/os',
      'content/eus/rhel/computenode/7/7.7/x86_64/source/SRPMS',
      'content/eus/rhel/power-le/7/7.7/ppc64le/debug',
      'content/eus/rhel/power-le/7/7.7/ppc64le/highavailability/debug',
      'content/eus/rhel/power-le/7/7.7/ppc64le/highavailability/os',
      'content/eus/rhel/power-le/7/7.7/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel/power-le/7/7.7/ppc64le/optional/debug',
      'content/eus/rhel/power-le/7/7.7/ppc64le/optional/os',
      'content/eus/rhel/power-le/7/7.7/ppc64le/optional/source/SRPMS',
      'content/eus/rhel/power-le/7/7.7/ppc64le/os',
      'content/eus/rhel/power-le/7/7.7/ppc64le/resilientstorage/debug',
      'content/eus/rhel/power-le/7/7.7/ppc64le/resilientstorage/os',
      'content/eus/rhel/power-le/7/7.7/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel/power-le/7/7.7/ppc64le/sap-hana/debug',
      'content/eus/rhel/power-le/7/7.7/ppc64le/sap-hana/os',
      'content/eus/rhel/power-le/7/7.7/ppc64le/sap-hana/source/SRPMS',
      'content/eus/rhel/power-le/7/7.7/ppc64le/sap/debug',
      'content/eus/rhel/power-le/7/7.7/ppc64le/sap/os',
      'content/eus/rhel/power-le/7/7.7/ppc64le/sap/source/SRPMS',
      'content/eus/rhel/power-le/7/7.7/ppc64le/source/SRPMS',
      'content/eus/rhel/power/7/7.7/ppc64/debug',
      'content/eus/rhel/power/7/7.7/ppc64/optional/debug',
      'content/eus/rhel/power/7/7.7/ppc64/optional/os',
      'content/eus/rhel/power/7/7.7/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/7/7.7/ppc64/os',
      'content/eus/rhel/power/7/7.7/ppc64/sap/debug',
      'content/eus/rhel/power/7/7.7/ppc64/sap/os',
      'content/eus/rhel/power/7/7.7/ppc64/sap/source/SRPMS',
      'content/eus/rhel/power/7/7.7/ppc64/source/SRPMS',
      'content/eus/rhel/server/7/7.7/x86_64/debug',
      'content/eus/rhel/server/7/7.7/x86_64/highavailability/debug',
      'content/eus/rhel/server/7/7.7/x86_64/highavailability/os',
      'content/eus/rhel/server/7/7.7/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/7/7.7/x86_64/optional/debug',
      'content/eus/rhel/server/7/7.7/x86_64/optional/os',
      'content/eus/rhel/server/7/7.7/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/7/7.7/x86_64/os',
      'content/eus/rhel/server/7/7.7/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/7/7.7/x86_64/resilientstorage/os',
      'content/eus/rhel/server/7/7.7/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/7/7.7/x86_64/sap-hana/debug',
      'content/eus/rhel/server/7/7.7/x86_64/sap-hana/os',
      'content/eus/rhel/server/7/7.7/x86_64/sap-hana/source/SRPMS',
      'content/eus/rhel/server/7/7.7/x86_64/sap/debug',
      'content/eus/rhel/server/7/7.7/x86_64/sap/os',
      'content/eus/rhel/server/7/7.7/x86_64/sap/source/SRPMS',
      'content/eus/rhel/server/7/7.7/x86_64/source/SRPMS',
      'content/tus/rhel/server/7/7.7/x86_64/debug',
      'content/tus/rhel/server/7/7.7/x86_64/highavailability/debug',
      'content/tus/rhel/server/7/7.7/x86_64/highavailability/os',
      'content/tus/rhel/server/7/7.7/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel/server/7/7.7/x86_64/optional/debug',
      'content/tus/rhel/server/7/7.7/x86_64/optional/os',
      'content/tus/rhel/server/7/7.7/x86_64/optional/source/SRPMS',
      'content/tus/rhel/server/7/7.7/x86_64/os',
      'content/tus/rhel/server/7/7.7/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'java-1.8.0-openjdk-1.8.0.242.b08-0.el7_7', 'sp':'7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-accessibility-1.8.0.242.b08-0.el7_7', 'sp':'7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-accessibility-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-accessibility-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-accessibility-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-accessibility-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-demo-1.8.0.242.b08-0.el7_7', 'sp':'7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-demo-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-demo-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-demo-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-demo-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-devel-1.8.0.242.b08-0.el7_7', 'sp':'7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-devel-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-devel-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-devel-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-devel-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-headless-1.8.0.242.b08-0.el7_7', 'sp':'7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-headless-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-headless-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-headless-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-headless-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-javadoc-1.8.0.242.b08-0.el7_7', 'sp':'7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-javadoc-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-javadoc-zip-1.8.0.242.b08-0.el7_7', 'sp':'7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-src-1.8.0.242.b08-0.el7_7', 'sp':'7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-src-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-src-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-src-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-src-debug-1.8.0.242.b08-0.el7_7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/supplementary/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/os',
      'content/dist/rhel/client/7/7Client/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/oracle-java-rm/os',
      'content/dist/rhel/client/7/7Client/x86_64/os',
      'content/dist/rhel/client/7/7Client/x86_64/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/debug',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/os',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/oracle-java-rm/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/os',
      'content/dist/rhel/power/7/7Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/os',
      'content/dist/rhel/power/7/7Server/ppc64/sap/debug',
      'content/dist/rhel/power/7/7Server/ppc64/sap/os',
      'content/dist/rhel/power/7/7Server/ppc64/sap/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/debug',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/os',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/os',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/debug',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/os',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/optional/debug',
      'content/dist/rhel/server/7/7Server/x86_64/optional/os',
      'content/dist/rhel/server/7/7Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/oracle-java-rm/os',
      'content/dist/rhel/server/7/7Server/x86_64/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rt/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rt/os',
      'content/dist/rhel/server/7/7Server/x86_64/rt/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/os',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/sap/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sap/os',
      'content/dist/rhel/server/7/7Server/x86_64/sap/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/debug',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/os',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/oracle-java-rm/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/os',
      'content/fastrack/rhel/client/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/os',
      'content/fastrack/rhel/client/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/os',
      'content/fastrack/rhel/computenode/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/os',
      'content/fastrack/rhel/computenode/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/os',
      'content/fastrack/rhel/power/7/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/os',
      'content/fastrack/rhel/power/7/ppc64/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/os',
      'content/fastrack/rhel/server/7/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/optional/debug',
      'content/fastrack/rhel/server/7/x86_64/optional/os',
      'content/fastrack/rhel/server/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/os',
      'content/fastrack/rhel/workstation/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/os',
      'content/fastrack/rhel/workstation/7/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'java-1.8.0-openjdk-1.8.0.242.b08-0.el7_7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-accessibility-1.8.0.242.b08-0.el7_7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-accessibility-debug-1.8.0.242.b08-0.el7_7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-accessibility-debug-1.8.0.242.b08-0.el7_7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-accessibility-debug-1.8.0.242.b08-0.el7_7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-accessibility-debug-1.8.0.242.b08-0.el7_7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-debug-1.8.0.242.b08-0.el7_7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-debug-1.8.0.242.b08-0.el7_7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-debug-1.8.0.242.b08-0.el7_7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-debug-1.8.0.242.b08-0.el7_7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-demo-1.8.0.242.b08-0.el7_7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-demo-debug-1.8.0.242.b08-0.el7_7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-demo-debug-1.8.0.242.b08-0.el7_7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-demo-debug-1.8.0.242.b08-0.el7_7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-demo-debug-1.8.0.242.b08-0.el7_7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-devel-1.8.0.242.b08-0.el7_7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-devel-debug-1.8.0.242.b08-0.el7_7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-devel-debug-1.8.0.242.b08-0.el7_7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-devel-debug-1.8.0.242.b08-0.el7_7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-devel-debug-1.8.0.242.b08-0.el7_7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-headless-1.8.0.242.b08-0.el7_7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-headless-debug-1.8.0.242.b08-0.el7_7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-headless-debug-1.8.0.242.b08-0.el7_7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-headless-debug-1.8.0.242.b08-0.el7_7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-headless-debug-1.8.0.242.b08-0.el7_7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-javadoc-1.8.0.242.b08-0.el7_7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-javadoc-debug-1.8.0.242.b08-0.el7_7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-javadoc-zip-1.8.0.242.b08-0.el7_7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.242.b08-0.el7_7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-src-1.8.0.242.b08-0.el7_7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-src-debug-1.8.0.242.b08-0.el7_7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-src-debug-1.8.0.242.b08-0.el7_7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-src-debug-1.8.0.242.b08-0.el7_7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-openjdk-src-debug-1.8.0.242.b08-0.el7_7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp']) && !enterprise_linux_flag) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / etc');
}
