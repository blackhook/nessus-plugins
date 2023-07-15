#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:3363. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152925);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2021-3609",
    "CVE-2021-22543",
    "CVE-2021-22555",
    "CVE-2021-32399"
  );
  script_xref(name:"RHSA", value:"2021:3363");

  script_name(english:"RHEL 8 : kernel (RHSA-2021:3363)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:3363 advisory.

  - kernel: Improper handling of VM_IO|VM_PFNMAP vmas in KVM can bypass RO checks (CVE-2021-22543)

  - kernel: out-of-bounds write in xt_compat_target_from_user() in net/netfilter/x_tables.c (CVE-2021-22555)

  - kernel: race condition for removal of the HCI controller (CVE-2021-32399)

  - kernel: race condition in net/can/bcm.c leads to local privilege escalation (CVE-2021-3609)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3609");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-22543");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-22555");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-32399");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:3363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1965461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1970807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1971651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1980101");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3609");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-22555");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Netfilter x_tables Heap OOB Write Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(362, 787, 863);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.2')) audit(AUDIT_OS_NOT, 'Red Hat 8.2', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-3609', 'CVE-2021-22543', 'CVE-2021-22555', 'CVE-2021-32399');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2021:3363');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.2/x86_64/appstream/debug',
      'content/aus/rhel8/8.2/x86_64/appstream/os',
      'content/aus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.2/x86_64/baseos/debug',
      'content/aus/rhel8/8.2/x86_64/baseos/os',
      'content/aus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.2/ppc64le/appstream/os',
      'content/e4s/rhel8/8.2/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.2/ppc64le/baseos/os',
      'content/e4s/rhel8/8.2/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.2/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.2/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.2/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.2/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/sap/debug',
      'content/e4s/rhel8/8.2/ppc64le/sap/os',
      'content/e4s/rhel8/8.2/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/appstream/debug',
      'content/e4s/rhel8/8.2/x86_64/appstream/os',
      'content/e4s/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/baseos/debug',
      'content/e4s/rhel8/8.2/x86_64/baseos/os',
      'content/e4s/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.2/x86_64/highavailability/os',
      'content/e4s/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/sap/debug',
      'content/e4s/rhel8/8.2/x86_64/sap/os',
      'content/e4s/rhel8/8.2/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/appstream/debug',
      'content/eus/rhel8/8.2/aarch64/appstream/os',
      'content/eus/rhel8/8.2/aarch64/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/baseos/debug',
      'content/eus/rhel8/8.2/aarch64/baseos/os',
      'content/eus/rhel8/8.2/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.2/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.2/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/highavailability/debug',
      'content/eus/rhel8/8.2/aarch64/highavailability/os',
      'content/eus/rhel8/8.2/aarch64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/supplementary/debug',
      'content/eus/rhel8/8.2/aarch64/supplementary/os',
      'content/eus/rhel8/8.2/aarch64/supplementary/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/appstream/debug',
      'content/eus/rhel8/8.2/ppc64le/appstream/os',
      'content/eus/rhel8/8.2/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/baseos/debug',
      'content/eus/rhel8/8.2/ppc64le/baseos/os',
      'content/eus/rhel8/8.2/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.2/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.2/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/highavailability/debug',
      'content/eus/rhel8/8.2/ppc64le/highavailability/os',
      'content/eus/rhel8/8.2/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/resilientstorage/debug',
      'content/eus/rhel8/8.2/ppc64le/resilientstorage/os',
      'content/eus/rhel8/8.2/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/sap-solutions/debug',
      'content/eus/rhel8/8.2/ppc64le/sap-solutions/os',
      'content/eus/rhel8/8.2/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/sap/debug',
      'content/eus/rhel8/8.2/ppc64le/sap/os',
      'content/eus/rhel8/8.2/ppc64le/sap/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/supplementary/debug',
      'content/eus/rhel8/8.2/ppc64le/supplementary/os',
      'content/eus/rhel8/8.2/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel8/8.2/s390x/appstream/debug',
      'content/eus/rhel8/8.2/s390x/appstream/os',
      'content/eus/rhel8/8.2/s390x/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/s390x/baseos/debug',
      'content/eus/rhel8/8.2/s390x/baseos/os',
      'content/eus/rhel8/8.2/s390x/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/s390x/codeready-builder/debug',
      'content/eus/rhel8/8.2/s390x/codeready-builder/os',
      'content/eus/rhel8/8.2/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/s390x/highavailability/debug',
      'content/eus/rhel8/8.2/s390x/highavailability/os',
      'content/eus/rhel8/8.2/s390x/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/s390x/resilientstorage/debug',
      'content/eus/rhel8/8.2/s390x/resilientstorage/os',
      'content/eus/rhel8/8.2/s390x/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.2/s390x/sap/debug',
      'content/eus/rhel8/8.2/s390x/sap/os',
      'content/eus/rhel8/8.2/s390x/sap/source/SRPMS',
      'content/eus/rhel8/8.2/s390x/supplementary/debug',
      'content/eus/rhel8/8.2/s390x/supplementary/os',
      'content/eus/rhel8/8.2/s390x/supplementary/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/appstream/debug',
      'content/eus/rhel8/8.2/x86_64/appstream/os',
      'content/eus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/baseos/debug',
      'content/eus/rhel8/8.2/x86_64/baseos/os',
      'content/eus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/highavailability/debug',
      'content/eus/rhel8/8.2/x86_64/highavailability/os',
      'content/eus/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/sap/debug',
      'content/eus/rhel8/8.2/x86_64/sap/os',
      'content/eus/rhel8/8.2/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/supplementary/debug',
      'content/eus/rhel8/8.2/x86_64/supplementary/os',
      'content/eus/rhel8/8.2/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/appstream/debug',
      'content/tus/rhel8/8.2/x86_64/appstream/os',
      'content/tus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/baseos/debug',
      'content/tus/rhel8/8.2/x86_64/baseos/os',
      'content/tus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/highavailability/debug',
      'content/tus/rhel8/8.2/x86_64/highavailability/os',
      'content/tus/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/nfv/debug',
      'content/tus/rhel8/8.2/x86_64/nfv/os',
      'content/tus/rhel8/8.2/x86_64/nfv/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/rt/debug',
      'content/tus/rhel8/8.2/x86_64/rt/os',
      'content/tus/rhel8/8.2/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-4.18.0-193.64.1.el8_2', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-4.18.0-193.64.1.el8_2', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-abi-whitelists-4.18.0-193.64.1.el8_2', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-core-4.18.0-193.64.1.el8_2', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-cross-headers-4.18.0-193.64.1.el8_2', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.18.0-193.64.1.el8_2', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-core-4.18.0-193.64.1.el8_2', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.18.0-193.64.1.el8_2', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-4.18.0-193.64.1.el8_2', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-extra-4.18.0-193.64.1.el8_2', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.18.0-193.64.1.el8_2', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-4.18.0-193.64.1.el8_2', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-extra-4.18.0-193.64.1.el8_2', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.18.0-193.64.1.el8_2', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-193.64.1.el8_2', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-193.64.1.el8_2', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-193.64.1.el8_2', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-193.64.1.el8_2', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-193.64.1.el8_2', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-193.64.1.el8_2', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-4.18.0-193.64.1.el8_2', 'sp':'2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-core-4.18.0-193.64.1.el8_2', 'sp':'2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-devel-4.18.0-193.64.1.el8_2', 'sp':'2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-4.18.0-193.64.1.el8_2', 'sp':'2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-193.64.1.el8_2', 'sp':'2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.18.0-193.64.1.el8_2', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-perf-4.18.0-193.64.1.el8_2', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Advanced Update Support, Extended Update Support, Telco Extended Update Support or Update Services for SAP Solutions repositories.\n' +
    'Access to these repositories requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get() + redhat_report_package_caveat();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / kernel-core / etc');
}
