#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:5068. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164846);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2022-1706",
    "CVE-2022-21698",
    "CVE-2022-23772",
    "CVE-2022-23773",
    "CVE-2022-23806",
    "CVE-2022-24675",
    "CVE-2022-24921",
    "CVE-2022-27191",
    "CVE-2022-28327",
    "CVE-2022-29162"
  );
  script_xref(name:"RHSA", value:"2022:5068");

  script_name(english:"RHEL 8 : OpenShift Container Platform 4.11.0 packages and (RHSA-2022:5068)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:5068 advisory.

  - golang.org/x/crypto: empty plaintext packet causes panic (CVE-2021-43565)

  - ignition: configs are accessible from unprivileged containers in VMs running on VMware products
    (CVE-2022-1706)

  - prometheus/client_golang: Denial of service using InstrumentHandlerCounter (CVE-2022-21698)

  - golang: math/big: uncontrolled memory consumption due to an unhandled overflow via Rat.SetString
    (CVE-2022-23772)

  - golang: cmd/go: misinterpretation of branch names can lead to incorrect access control (CVE-2022-23773)

  - golang: crypto/elliptic: IsOnCurve returns true for invalid field elements (CVE-2022-23806)

  - golang: encoding/pem: fix stack overflow in Decode (CVE-2022-24675)

  - golang: regexp: stack exhaustion via a deeply nested expression (CVE-2022-24921)

  - golang: crash in a golang.org/x/crypto/ssh server (CVE-2022-27191)

  - golang: crypto/elliptic: panic caused by oversized scalar (CVE-2022-28327)

  - runc: incorrect handling of inheritable capabilities (CVE-2022-29162)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-43565");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1706");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21698");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23772");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23773");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23806");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-24675");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-24921");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27191");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-28327");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-29162");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:5068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2030787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2045880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2053429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2053532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2053541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2064702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2064857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2077688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2077689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2086398");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23806");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 120, 190, 200, 252, 276, 327, 400, 772, 863, 1220);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:butane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:butane-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ignition");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ignition-validate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-hyperkube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo-tests");
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
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/rhocp/4.11/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.11/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.11/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'buildah-1.23.4-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube'},
      {'reference':'buildah-tests-1.23.4-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube'},
      {'reference':'butane-0.15.0-1.rhaos4.11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'butane-redistributable-0.15.0-1.rhaos4.11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'containernetworking-plugins-1.0.1-5.rhaos4.11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'cri-o-1.24.1-11.rhaos4.11.gitb0d2ef3.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'ignition-2.14.0-3.rhaos4.11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'ignition-validate-2.14.0-3.rhaos4.11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'openshift-clients-4.11.0-202207291716.p0.g7075089.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'openshift-clients-redistributable-4.11.0-202207291716.p0.g7075089.assembly.stream.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'openshift-hyperkube-4.11.0-202207082037.p0.g9546431.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'podman-4.0.2-6.rhaos4.11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
      {'reference':'podman-catatonit-4.0.2-6.rhaos4.11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
      {'reference':'podman-docker-4.0.2-6.rhaos4.11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
      {'reference':'podman-plugins-4.0.2-6.rhaos4.11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
      {'reference':'podman-remote-4.0.2-6.rhaos4.11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
      {'reference':'podman-tests-4.0.2-6.rhaos4.11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
      {'reference':'runc-1.1.2-1.rhaos4.11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
      {'reference':'skopeo-1.5.2-3.rhaos4.11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
      {'reference':'skopeo-tests-1.5.2-3.rhaos4.11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'buildah / buildah-tests / butane / butane-redistributable / etc');
}
