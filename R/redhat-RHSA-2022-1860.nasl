##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:1860. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161010);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2020-13956");
  script_xref(name:"IAVA", value:"2022-A-0029");
  script_xref(name:"RHSA", value:"2022:1860");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 8 : maven:3.6 (RHSA-2022:1860)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2022:1860 advisory.

  - apache-httpclient: incorrect handling of malformed authority component in request URIs (CVE-2020-13956)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-13956");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:1860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1886587");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13956");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:aopalliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-lang3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atinject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cdi-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:geronimo-annotation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:google-guice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:guava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcl-over-slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jsoup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jsr-305");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-openjdk11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-openjdk17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-openjdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-shared-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-wagon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-cipher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-classworlds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-containers-component-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-interpolation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-sec-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sisu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'maven:3.6': [
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.6/x86_64/appstream/debug',
        'content/aus/rhel8/8.6/x86_64/appstream/os',
        'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.6/x86_64/baseos/debug',
        'content/aus/rhel8/8.6/x86_64/baseos/os',
        'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.6/ppc64le/appstream/os',
        'content/e4s/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/baseos/debug',
        'content/e4s/rhel8/8.6/ppc64le/baseos/os',
        'content/e4s/rhel8/8.6/ppc64le/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/debug',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/os',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/debug',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/os',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/sap/debug',
        'content/e4s/rhel8/8.6/ppc64le/sap/os',
        'content/e4s/rhel8/8.6/ppc64le/sap/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/appstream/debug',
        'content/e4s/rhel8/8.6/x86_64/appstream/os',
        'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/baseos/debug',
        'content/e4s/rhel8/8.6/x86_64/baseos/os',
        'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.6/x86_64/highavailability/os',
        'content/e4s/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/sap/debug',
        'content/e4s/rhel8/8.6/x86_64/sap/os',
        'content/e4s/rhel8/8.6/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/appstream/debug',
        'content/eus/rhel8/8.6/aarch64/appstream/os',
        'content/eus/rhel8/8.6/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/baseos/debug',
        'content/eus/rhel8/8.6/aarch64/baseos/os',
        'content/eus/rhel8/8.6/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/highavailability/debug',
        'content/eus/rhel8/8.6/aarch64/highavailability/os',
        'content/eus/rhel8/8.6/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/supplementary/debug',
        'content/eus/rhel8/8.6/aarch64/supplementary/os',
        'content/eus/rhel8/8.6/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/appstream/debug',
        'content/eus/rhel8/8.6/ppc64le/appstream/os',
        'content/eus/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/baseos/debug',
        'content/eus/rhel8/8.6/ppc64le/baseos/os',
        'content/eus/rhel8/8.6/ppc64le/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/debug',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/os',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/highavailability/debug',
        'content/eus/rhel8/8.6/ppc64le/highavailability/os',
        'content/eus/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/debug',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/os',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/debug',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/os',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/sap/debug',
        'content/eus/rhel8/8.6/ppc64le/sap/os',
        'content/eus/rhel8/8.6/ppc64le/sap/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/supplementary/debug',
        'content/eus/rhel8/8.6/ppc64le/supplementary/os',
        'content/eus/rhel8/8.6/ppc64le/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/appstream/debug',
        'content/eus/rhel8/8.6/s390x/appstream/os',
        'content/eus/rhel8/8.6/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/baseos/debug',
        'content/eus/rhel8/8.6/s390x/baseos/os',
        'content/eus/rhel8/8.6/s390x/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/codeready-builder/debug',
        'content/eus/rhel8/8.6/s390x/codeready-builder/os',
        'content/eus/rhel8/8.6/s390x/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/highavailability/debug',
        'content/eus/rhel8/8.6/s390x/highavailability/os',
        'content/eus/rhel8/8.6/s390x/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/resilientstorage/debug',
        'content/eus/rhel8/8.6/s390x/resilientstorage/os',
        'content/eus/rhel8/8.6/s390x/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/sap/debug',
        'content/eus/rhel8/8.6/s390x/sap/os',
        'content/eus/rhel8/8.6/s390x/sap/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/supplementary/debug',
        'content/eus/rhel8/8.6/s390x/supplementary/os',
        'content/eus/rhel8/8.6/s390x/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/appstream/debug',
        'content/eus/rhel8/8.6/x86_64/appstream/os',
        'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/baseos/debug',
        'content/eus/rhel8/8.6/x86_64/baseos/os',
        'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/highavailability/debug',
        'content/eus/rhel8/8.6/x86_64/highavailability/os',
        'content/eus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/sap/debug',
        'content/eus/rhel8/8.6/x86_64/sap/os',
        'content/eus/rhel8/8.6/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/supplementary/debug',
        'content/eus/rhel8/8.6/x86_64/supplementary/os',
        'content/eus/rhel8/8.6/x86_64/supplementary/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/appstream/debug',
        'content/tus/rhel8/8.6/x86_64/appstream/os',
        'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/baseos/debug',
        'content/tus/rhel8/8.6/x86_64/baseos/os',
        'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/highavailability/debug',
        'content/tus/rhel8/8.6/x86_64/highavailability/os',
        'content/tus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/rt/os',
        'content/tus/rhel8/8.6/x86_64/rt/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'aopalliance-1.0-20.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-cli-1.4-7.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-codec-1.13-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-io-2.6-6.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'apache-commons-lang3-3.9-4.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'atinject-1-31.20100611svn86.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
        {'reference':'cdi-api-2.0.1-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'geronimo-annotation-1.0-26.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'google-guice-4.2.2-4.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'guava-28.1-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpcomponents-client-4.5.10-4.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpcomponents-core-4.4.12-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jansi-1.18-4.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jcl-over-slf4j-1.7.28-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jsoup-1.12.1-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jsr-305-0-0.25.20130910svn.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-lib-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-openjdk11-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-openjdk17-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-openjdk8-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-resolver-1.4.1-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-shared-utils-3.2.1-0.4.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-wagon-3.3.4-2.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-cipher-1.7-17.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-classworlds-2.6.0-4.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-containers-component-annotations-2.1.0-2.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-interpolation-1.26-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-sec-dispatcher-1.4-29.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-utils-3.3.0-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'sisu-0.3.4-2.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'slf4j-1.7.28-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    },
    {
      'repo_relative_urls': [
        'content/dist/rhel8/8/aarch64/appstream/debug',
        'content/dist/rhel8/8/aarch64/appstream/os',
        'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8/aarch64/baseos/debug',
        'content/dist/rhel8/8/aarch64/baseos/os',
        'content/dist/rhel8/8/aarch64/baseos/source/SRPMS',
        'content/dist/rhel8/8/aarch64/codeready-builder/debug',
        'content/dist/rhel8/8/aarch64/codeready-builder/os',
        'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/aarch64/highavailability/debug',
        'content/dist/rhel8/8/aarch64/highavailability/os',
        'content/dist/rhel8/8/aarch64/highavailability/source/SRPMS',
        'content/dist/rhel8/8/aarch64/supplementary/debug',
        'content/dist/rhel8/8/aarch64/supplementary/os',
        'content/dist/rhel8/8/aarch64/supplementary/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/appstream/debug',
        'content/dist/rhel8/8/ppc64le/appstream/os',
        'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/baseos/debug',
        'content/dist/rhel8/8/ppc64le/baseos/os',
        'content/dist/rhel8/8/ppc64le/baseos/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/codeready-builder/debug',
        'content/dist/rhel8/8/ppc64le/codeready-builder/os',
        'content/dist/rhel8/8/ppc64le/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/highavailability/debug',
        'content/dist/rhel8/8/ppc64le/highavailability/os',
        'content/dist/rhel8/8/ppc64le/highavailability/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/resilientstorage/debug',
        'content/dist/rhel8/8/ppc64le/resilientstorage/os',
        'content/dist/rhel8/8/ppc64le/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/sap-solutions/debug',
        'content/dist/rhel8/8/ppc64le/sap-solutions/os',
        'content/dist/rhel8/8/ppc64le/sap-solutions/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/sap/debug',
        'content/dist/rhel8/8/ppc64le/sap/os',
        'content/dist/rhel8/8/ppc64le/sap/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/supplementary/debug',
        'content/dist/rhel8/8/ppc64le/supplementary/os',
        'content/dist/rhel8/8/ppc64le/supplementary/source/SRPMS',
        'content/dist/rhel8/8/s390x/appstream/debug',
        'content/dist/rhel8/8/s390x/appstream/os',
        'content/dist/rhel8/8/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8/s390x/baseos/debug',
        'content/dist/rhel8/8/s390x/baseos/os',
        'content/dist/rhel8/8/s390x/baseos/source/SRPMS',
        'content/dist/rhel8/8/s390x/codeready-builder/debug',
        'content/dist/rhel8/8/s390x/codeready-builder/os',
        'content/dist/rhel8/8/s390x/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/s390x/highavailability/debug',
        'content/dist/rhel8/8/s390x/highavailability/os',
        'content/dist/rhel8/8/s390x/highavailability/source/SRPMS',
        'content/dist/rhel8/8/s390x/resilientstorage/debug',
        'content/dist/rhel8/8/s390x/resilientstorage/os',
        'content/dist/rhel8/8/s390x/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/s390x/sap/debug',
        'content/dist/rhel8/8/s390x/sap/os',
        'content/dist/rhel8/8/s390x/sap/source/SRPMS',
        'content/dist/rhel8/8/s390x/supplementary/debug',
        'content/dist/rhel8/8/s390x/supplementary/os',
        'content/dist/rhel8/8/s390x/supplementary/source/SRPMS',
        'content/dist/rhel8/8/x86_64/appstream/debug',
        'content/dist/rhel8/8/x86_64/appstream/os',
        'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8/x86_64/baseos/debug',
        'content/dist/rhel8/8/x86_64/baseos/os',
        'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
        'content/dist/rhel8/8/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8/x86_64/codeready-builder/os',
        'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/x86_64/highavailability/debug',
        'content/dist/rhel8/8/x86_64/highavailability/os',
        'content/dist/rhel8/8/x86_64/highavailability/source/SRPMS',
        'content/dist/rhel8/8/x86_64/nfv/debug',
        'content/dist/rhel8/8/x86_64/nfv/os',
        'content/dist/rhel8/8/x86_64/nfv/source/SRPMS',
        'content/dist/rhel8/8/x86_64/resilientstorage/debug',
        'content/dist/rhel8/8/x86_64/resilientstorage/os',
        'content/dist/rhel8/8/x86_64/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/x86_64/rt/debug',
        'content/dist/rhel8/8/x86_64/rt/os',
        'content/dist/rhel8/8/x86_64/rt/source/SRPMS',
        'content/dist/rhel8/8/x86_64/sap-solutions/debug',
        'content/dist/rhel8/8/x86_64/sap-solutions/os',
        'content/dist/rhel8/8/x86_64/sap-solutions/source/SRPMS',
        'content/dist/rhel8/8/x86_64/sap/debug',
        'content/dist/rhel8/8/x86_64/sap/os',
        'content/dist/rhel8/8/x86_64/sap/source/SRPMS',
        'content/dist/rhel8/8/x86_64/supplementary/debug',
        'content/dist/rhel8/8/x86_64/supplementary/os',
        'content/dist/rhel8/8/x86_64/supplementary/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'aopalliance-1.0-20.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-cli-1.4-7.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-codec-1.13-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-io-2.6-6.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'apache-commons-lang3-3.9-4.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'atinject-1-31.20100611svn86.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
        {'reference':'cdi-api-2.0.1-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'geronimo-annotation-1.0-26.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'google-guice-4.2.2-4.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'guava-28.1-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpcomponents-client-4.5.10-4.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpcomponents-core-4.4.12-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jansi-1.18-4.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jcl-over-slf4j-1.7.28-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jsoup-1.12.1-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jsr-305-0-0.25.20130910svn.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-lib-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-openjdk11-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-openjdk17-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-openjdk8-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-resolver-1.4.1-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-shared-utils-3.2.1-0.4.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-wagon-3.3.4-2.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-cipher-1.7-17.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-classworlds-2.6.0-4.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-containers-component-annotations-2.1.0-2.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-interpolation-1.26-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-sec-dispatcher-1.4-29.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-utils-3.3.0-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'sisu-0.3.4-2.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'slf4j-1.7.28-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/maven');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module maven:3.6');
if ('3.6' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module maven:' + module_ver);

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var module_array ( appstreams[module] ) {
      var repo_relative_urls = NULL;
      if (!empty_or_null(module_array['repo_relative_urls'])) repo_relative_urls = module_array['repo_relative_urls'];
      var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
      foreach var package_array ( module_array['pkgs'] ) {
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
        if (!empty_or_null(package_array['release'])) _release = 'RHEL' + package_array['release'];
        if (!empty_or_null(package_array['sp']) && !enterprise_linux_flag) sp = package_array['sp'];
        if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
        if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
        if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
        if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
        if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
        if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
        if (reference &&
            _release &&
            rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
            (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
            rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module maven:3.6');

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aopalliance / apache-commons-cli / apache-commons-codec / etc');
}
