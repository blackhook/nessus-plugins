##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:0423. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146566);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2020-1945",
    "CVE-2020-11979",
    "CVE-2021-21602",
    "CVE-2021-21603",
    "CVE-2021-21604",
    "CVE-2021-21605",
    "CVE-2021-21606",
    "CVE-2021-21607",
    "CVE-2021-21608",
    "CVE-2021-21609",
    "CVE-2021-21610",
    "CVE-2021-21611",
    "CVE-2021-21615"
  );
  script_xref(name:"IAVA", value:"2020-A-0324");
  script_xref(name:"RHSA", value:"2021:0423");
  script_xref(name:"IAVA", value:"2021-A-0196");
  script_xref(name:"IAVA", value:"2021-A-0039-S");
  script_xref(name:"IAVA", value:"2021-A-0035-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 7 / 8 : OpenShift Container Platform 4.6.17 (RHSA-2021:0423)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:0423 advisory.

  - ant: insecure temporary file (CVE-2020-11979)

  - ant: insecure temporary file vulnerability (CVE-2020-1945)

  - jenkins: Arbitrary file read vulnerability in workspace browsers (CVE-2021-21602)

  - jenkins:  XSS vulnerability in notification bar (CVE-2021-21603)

  - jenkins:  Improper handling of REST API XML deserialization errors (CVE-2021-21604)

  - jenkins:  Path traversal vulnerability in agent names (CVE-2021-21605)

  - jenkins:  Arbitrary file existence check in file fingerprints (CVE-2021-21606)

  - jenkins:  Excessive memory allocation in graph URLs leads to denial of service (CVE-2021-21607)

  - jenkins: Stored XSS vulnerability in button labels (CVE-2021-21608)

  - jenkins:  Missing permission check for paths with specific prefix (CVE-2021-21609)

  - jenkins:  Reflected XSS vulnerability in markup formatter preview (CVE-2021-21610)

  - jenkins:  Stored XSS vulnerability on new item page (CVE-2021-21611)

  - jenkins: Filesystem traversal by privileged users (CVE-2021-21615)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1945");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11979");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21602");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21603");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21604");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21605");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21606");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21607");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21608");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21609");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21610");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21611");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21615");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:0423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1903702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1921322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1925140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1925141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1925143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1925145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1925151");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1925156");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1925157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1925159");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1925160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1925161");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21605");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 22, 59, 79, 377, 502, 770, 863);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-service-idler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-2-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-hyperkube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-kuryr-cni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-kuryr-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-kuryr-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-kuryr-kubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:runc");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['7','8'])) audit(AUDIT_OS_NOT, 'Red Hat 7.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/ppc64le/rhocp/4.3/debug',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.3/os',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.3/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.4/debug',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.4/os',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.4/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.5/debug',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.5/os',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.5/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.6/debug',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.6/os',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.6/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.7/debug',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.7/os',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.7/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhocp/4.2/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.2/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.2/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhocp/4.3/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.3/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.3/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhocp/4.4/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.4/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.4/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhocp/4.5/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.5/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.5/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhocp/4.6/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.6/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.6/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhocp/4.7/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.7/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.7/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.1/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.1/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.1/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.2/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.2/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.2/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.3/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.3/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.3/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.4/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.4/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.5/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.5/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.5/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.6/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.6/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.6/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.7/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.7/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.7/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'atomic-openshift-service-idler-4.6.0-202102031810.p0.git.15.dcab90a.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'atomic-openshift-service-idler-4.6.0-202102031810.p0.git.15.dcab90a.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'atomic-openshift-service-idler-4.6.0-202102031810.p0.git.15.dcab90a.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jenkins-2-plugins-4.6.1612257979-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jenkins-2.263.3.1612434510-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openshift-clients-4.6.0-202102050644.p0.git.3831.1c61c6b.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openshift-clients-4.6.0-202102050644.p0.git.3831.1c61c6b.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openshift-clients-4.6.0-202102050644.p0.git.3831.1c61c6b.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openshift-clients-redistributable-4.6.0-202102050644.p0.git.3831.1c61c6b.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openshift-hyperkube-4.6.0-202102050212.p0.git.94265.716fcf8.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openshift-hyperkube-4.6.0-202102050212.p0.git.94265.716fcf8.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openshift-hyperkube-4.6.0-202102050212.p0.git.94265.716fcf8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openshift-kuryr-cni-4.6.0-202102031810.p0.git.2225.a3ab872.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openshift-kuryr-common-4.6.0-202102031810.p0.git.2225.a3ab872.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openshift-kuryr-controller-4.6.0-202102031810.p0.git.2225.a3ab872.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-kuryr-kubernetes-4.6.0-202102031810.p0.git.2225.a3ab872.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-rsa-4.7-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.0-82.rhaos4.6.git086e841.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.0-82.rhaos4.6.git086e841.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.0-82.rhaos4.6.git086e841.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/ose/4.1/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/ose/4.1/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/ose/4.1/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.1/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.1/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.1/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.3/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.3/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.3/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.4/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.4/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.4/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.5/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.5/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.5/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.6/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.6/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.6/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.7/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.7/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.7/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.1/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.1/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.2/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.2/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.2/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.3/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.4/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.5/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.5/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.5/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.6/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.6/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.6/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.7/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.7/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.7/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.2/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.2/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.2/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.3/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.3/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.3/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.4/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.4/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.4/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.5/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.5/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.5/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.6/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.6/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.6/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.7/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.7/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.7/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'cri-o-1.19.1-7.rhaos4.6.git6377f68.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openshift-ansible-4.6.0-202102031649.p0.git.0.bf90f86.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openshift-ansible-test-4.6.0-202102031649.p0.git.0.bf90f86.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openshift-clients-4.6.0-202102050644.p0.git.3831.1c61c6b.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openshift-clients-redistributable-4.6.0-202102050644.p0.git.3831.1c61c6b.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openshift-hyperkube-4.6.0-202102050212.p0.git.94265.716fcf8.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.0-82.rhaos4.6.git086e841.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
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
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'atomic-openshift-service-idler / cri-o / jenkins / jenkins-2-plugins / etc');
}
