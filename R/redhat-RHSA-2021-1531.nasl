#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:1531. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149444);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2019-19532",
    "CVE-2020-25211",
    "CVE-2020-25705",
    "CVE-2020-28374",
    "CVE-2021-27363",
    "CVE-2021-27364",
    "CVE-2021-27365"
  );
  script_xref(name:"RHSA", value:"2021:1531");
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"RHEL 7 : kernel (RHSA-2021:1531)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:1531 advisory.

  - kernel: malicious USB devices can lead to multiple out-of-bounds write (CVE-2019-19532)

  - kernel: Local buffer overflow in ctnetlink_parse_tuple_filter in net/netfilter/nf_conntrack_netlink.c
    (CVE-2020-25211)

  - kernel: ICMP rate limiting can be used for DNS poisoning attack (CVE-2020-25705)

  - kernel: SCSI target (LIO) write to any block on ILO backstore (CVE-2020-28374)

  - kernel: iscsi: unrestricted access to sessions and handles (CVE-2021-27363)

  - kernel: out-of-bounds read in libiscsi module (CVE-2021-27364)

  - kernel: heap buffer overflow in the iSCSI subsystem (CVE-2021-27365)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19532");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25211");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25705");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-28374");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-27363");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-27364");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-27365");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:1531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1781821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1877571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1894579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1899804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1930078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1930079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1930080");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25705");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-28374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 122, 125, 200, 250, 330);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:7.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:7.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:7.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:7.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-bootwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '7.7')) audit(AUDIT_OS_NOT, 'Red Hat 7.7', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2019-19532', 'CVE-2020-25211', 'CVE-2020-25705', 'CVE-2020-28374', 'CVE-2021-27363', 'CVE-2021-27364', 'CVE-2021-27365');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2021:1531');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

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
      'content/eus/rhel/system-z/7/7.7/s390x/debug',
      'content/eus/rhel/system-z/7/7.7/s390x/optional/debug',
      'content/eus/rhel/system-z/7/7.7/s390x/optional/os',
      'content/eus/rhel/system-z/7/7.7/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/7/7.7/s390x/os',
      'content/eus/rhel/system-z/7/7.7/s390x/sap/debug',
      'content/eus/rhel/system-z/7/7.7/s390x/sap/os',
      'content/eus/rhel/system-z/7/7.7/s390x/sap/source/SRPMS',
      'content/eus/rhel/system-z/7/7.7/s390x/source/SRPMS',
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
      {'reference':'bpftool-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bpftool-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bpftool-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bpftool-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-abi-whitelists-3.10.0-1062.49.1.el7', 'sp':'7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-1062.49.1.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / kernel-bootwrapper / etc');
}