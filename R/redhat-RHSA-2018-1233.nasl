##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:1233. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(119395);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/21");

  script_cve_id("CVE-2018-1102");
  script_xref(name:"RHSA", value:"2018:1233");

  script_name(english:"RHEL 7 : OpenShift Container Platform 3.6 (RHSA-2018:1233)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2018:1233 advisory.

  - source-to-image: Improper path sanitization in ExtractTarStreamFromTarReader in tar/tar.go (CVE-2018-1102)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/20.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-1102");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:1233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1562246");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1102");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-cluster-capacity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-docker-excluder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-dockerregistry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-excluder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-federation-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-pod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-sdn-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-service-catalog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-cool.io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-cool.io-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-excon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-excon-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fluent-plugin-kubernetes_metadata_filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fluent-plugin-kubernetes_metadata_filter-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fluent-plugin-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fluent-plugin-systemd-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-minitest-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-msgpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-msgpack-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-multi_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-multi_json-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-systemd-journal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-systemd-journal-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tzinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tzinfo-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tzinfo-data-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tzinfo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-unf_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-unf_ext-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tuned-profiles-atomic-openshift-node");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Red Hat' >!< release) audit(AUDIT_OS_NOT, 'Red Hat');
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

repositories = {
    'openshift_3_6_el7': [
      'rhel-7-server-ose-3.6-debug-rpms',
      'rhel-7-server-ose-3.6-rpms',
      'rhel-7-server-ose-3.6-source-rpms'
    ]
};

found_repos = NULL;
host_repo_list = get_kb_list('Host/RedHat/repo-list/*');
if (!(empty_or_null(host_repo_list))) {
  found_repos = make_list();
  foreach repo_key (keys(repositories)) {
    foreach repo ( repositories[repo_key] ) {
      if (get_kb_item('Host/RedHat/repo-list/' + repo)) {
        append_element(var:found_repos, value:repo_key);
        break;
      }
    }
  }
  if(empty_or_null(found_repos)) audit(AUDIT_RHSA_NOT_AFFECTED, 'RHSA-2018:1233');
}

pkgs = [
    {'reference':'atomic-openshift-3.6.173.0.113-1.git.0.65fb9fb.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'atomic-openshift-clients-3.6.173.0.113-1.git.0.65fb9fb.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'atomic-openshift-clients-redistributable-3.6.173.0.113-1.git.0.65fb9fb.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'atomic-openshift-cluster-capacity-3.6.173.0.113-1.git.0.65fb9fb.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'atomic-openshift-docker-excluder-3.6.173.0.113-1.git.0.65fb9fb.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'atomic-openshift-dockerregistry-3.6.173.0.113-1.git.0.65fb9fb.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'atomic-openshift-excluder-3.6.173.0.113-1.git.0.65fb9fb.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'atomic-openshift-federation-services-3.6.173.0.113-1.git.0.65fb9fb.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'atomic-openshift-master-3.6.173.0.113-1.git.0.65fb9fb.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'atomic-openshift-node-3.6.173.0.113-1.git.0.65fb9fb.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'atomic-openshift-pod-3.6.173.0.113-1.git.0.65fb9fb.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'atomic-openshift-sdn-ovs-3.6.173.0.113-1.git.0.65fb9fb.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'atomic-openshift-service-catalog-3.6.173.0.113-1.git.0.65fb9fb.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'atomic-openshift-tests-3.6.173.0.113-1.git.0.65fb9fb.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-cool.io-1.5.3-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-cool.io-doc-1.5.3-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-excon-0.60.0-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-excon-doc-0.60.0-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-faraday-0.13.1-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-faraday-doc-0.13.1-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-ffi-1.9.23-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-fluent-plugin-kubernetes_metadata_filter-1.0.1-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-fluent-plugin-kubernetes_metadata_filter-doc-1.0.1-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-fluent-plugin-systemd-0.0.9-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-fluent-plugin-systemd-doc-0.0.9-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-minitest-5.10.3-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-minitest-doc-5.10.3-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-msgpack-1.2.2-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-msgpack-doc-1.2.2-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-multi_json-1.13.1-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-multi_json-doc-1.13.1-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-systemd-journal-1.3.1-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-systemd-journal-doc-1.3.1-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-tzinfo-1.2.5-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-tzinfo-data-1.2018.3-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-tzinfo-data-doc-1.2018.3-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-tzinfo-doc-1.2.5-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-unf_ext-0.0.7.5-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'rubygem-unf_ext-doc-0.0.7.5-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']},
    {'reference':'tuned-profiles-atomic-openshift-node-3.6.173.0.113-1.git.0.65fb9fb.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['openshift_3_6_el7']}
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
  repo_list = NULL;
  if (!empty_or_null(package_array['repo_list'])) repo_list = package_array['repo_list'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'RHEL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    repocheck = FALSE;
    if (empty_or_null(found_repos))
    {
      repocheck = TRUE;
    }
    else
    {
      foreach repo (repo_list) {
        if (contains_element(var:found_repos, value:repo))
        {
          repocheck = TRUE;
          break;
        }
      }
    }
    if (repocheck && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  if (empty_or_null(host_repo_list)) extra = rpm_report_get() + redhat_report_repo_caveat();
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'atomic-openshift / atomic-openshift-clients / etc');
}
