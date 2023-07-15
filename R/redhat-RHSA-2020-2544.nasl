##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2544. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(137410);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2020-6465",
    "CVE-2020-6466",
    "CVE-2020-6467",
    "CVE-2020-6468",
    "CVE-2020-6469",
    "CVE-2020-6470",
    "CVE-2020-6471",
    "CVE-2020-6472",
    "CVE-2020-6473",
    "CVE-2020-6474",
    "CVE-2020-6475",
    "CVE-2020-6476",
    "CVE-2020-6478",
    "CVE-2020-6479",
    "CVE-2020-6480",
    "CVE-2020-6481",
    "CVE-2020-6482",
    "CVE-2020-6483",
    "CVE-2020-6484",
    "CVE-2020-6485",
    "CVE-2020-6486",
    "CVE-2020-6487",
    "CVE-2020-6488",
    "CVE-2020-6489",
    "CVE-2020-6490",
    "CVE-2020-6491",
    "CVE-2020-6493",
    "CVE-2020-6494",
    "CVE-2020-6495",
    "CVE-2020-6496"
  );
  script_xref(name:"RHSA", value:"2020:2544");
  script_xref(name:"IAVA", value:"2020-A-0220-S");
  script_xref(name:"IAVA", value:"2020-A-0241-S");

  script_name(english:"RHEL 6 : chromium-browser (RHSA-2020:2544)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has a package installed that is affected by multiple vulnerabilities as
referenced in the RHSA-2020:2544 advisory.

  - chromium-browser: Use after free in reader mode (CVE-2020-6465)

  - chromium-browser: Use after free in media (CVE-2020-6466)

  - chromium-browser: Use after free in WebRTC (CVE-2020-6467)

  - chromium-browser: Type Confusion in V8 (CVE-2020-6468)

  - chromium-browser: Insufficient policy enforcement in developer tools (CVE-2020-6469, CVE-2020-6471,
    CVE-2020-6472, CVE-2020-6482, CVE-2020-6495)

  - chromium-browser: Insufficient validation of untrusted input in clipboard (CVE-2020-6470)

  - chromium-browser: Insufficient policy enforcement in Blink (CVE-2020-6473)

  - chromium-browser: Use after free in Blink (CVE-2020-6474)

  - chromium-browser: Incorrect security UI in full screen (CVE-2020-6475)

  - chromium-browser: Insufficient policy enforcement in tab strip (CVE-2020-6476)

  - chromium-browser: Inappropriate implementation in full screen (CVE-2020-6478)

  - chromium-browser: Inappropriate implementation in sharing (CVE-2020-6479)

  - chromium-browser: Insufficient policy enforcement in enterprise (CVE-2020-6480)

  - chromium-browser: Insufficient policy enforcement in URL formatting (CVE-2020-6481)

  - chromium-browser: Insufficient policy enforcement in payments (CVE-2020-6483)

  - chromium-browser: Insufficient data validation in ChromeDriver (CVE-2020-6484)

  - chromium-browser: Insufficient data validation in media router (CVE-2020-6485)

  - chromium-browser: Insufficient policy enforcement in navigations (CVE-2020-6486)

  - chromium-browser: Insufficient policy enforcement in downloads (CVE-2020-6487, CVE-2020-6488)

  - chromium-browser: Inappropriate implementation in developer tools (CVE-2020-6489)

  - chromium-browser: Insufficient data validation in loader (CVE-2020-6490)

  - chromium-browser: Incorrect security UI in site information (CVE-2020-6491)

  - chromium-browser: Use after free in WebAuthentication (CVE-2020-6493)

  - chromium-browser: Incorrect security UI in payments (CVE-2020-6494)

  - chromium-browser: Use after free in payments (CVE-2020-6496)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6465");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6466");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6467");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6468");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6469");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6470");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6471");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6472");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6473");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6474");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6475");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6476");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6478");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6479");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6480");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6481");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6482");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6483");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6484");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6485");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6486");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6487");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6488");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6489");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6490");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6491");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6493");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6494");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6495");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6496");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:2544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1844554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1844555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1844556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1844557");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium-browser package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6496");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-6493");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_els:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:chromium-browser");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/6/6Client/i386/debug',
      'content/dist/rhel/client/6/6Client/i386/optional/debug',
      'content/dist/rhel/client/6/6Client/i386/optional/os',
      'content/dist/rhel/client/6/6Client/i386/optional/source/SRPMS',
      'content/dist/rhel/client/6/6Client/i386/oracle-java-rm/os',
      'content/dist/rhel/client/6/6Client/i386/oracle-java-rm/source/SRPMS',
      'content/dist/rhel/client/6/6Client/i386/os',
      'content/dist/rhel/client/6/6Client/i386/source/SRPMS',
      'content/dist/rhel/client/6/6Client/i386/supplementary/debug',
      'content/dist/rhel/client/6/6Client/i386/supplementary/os',
      'content/dist/rhel/client/6/6Client/i386/supplementary/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/debug',
      'content/dist/rhel/client/6/6Client/x86_64/optional/debug',
      'content/dist/rhel/client/6/6Client/x86_64/optional/os',
      'content/dist/rhel/client/6/6Client/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/oracle-java-rm/os',
      'content/dist/rhel/client/6/6Client/x86_64/oracle-java-rm/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/os',
      'content/dist/rhel/client/6/6Client/x86_64/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/supplementary/debug',
      'content/dist/rhel/client/6/6Client/x86_64/supplementary/os',
      'content/dist/rhel/client/6/6Client/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/hpn/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/hpn/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/hpn/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/optional/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/optional/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/optional/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/oracle-java-rm/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/oracle-java-rm/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/scalablefilesystem/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/supplementary/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/supplementary/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/debug',
      'content/dist/rhel/server/6/6Server/i386/highavailability/debug',
      'content/dist/rhel/server/6/6Server/i386/highavailability/os',
      'content/dist/rhel/server/6/6Server/i386/highavailability/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/debug',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/os',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/optional/debug',
      'content/dist/rhel/server/6/6Server/i386/optional/os',
      'content/dist/rhel/server/6/6Server/i386/optional/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/oracle-java-rm/os',
      'content/dist/rhel/server/6/6Server/i386/oracle-java-rm/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/os',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/debug',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/os',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/supplementary/debug',
      'content/dist/rhel/server/6/6Server/i386/supplementary/os',
      'content/dist/rhel/server/6/6Server/i386/supplementary/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/debug',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/os',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/hpn/debug',
      'content/dist/rhel/server/6/6Server/x86_64/hpn/os',
      'content/dist/rhel/server/6/6Server/x86_64/hpn/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/debug',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/os',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/optional/debug',
      'content/dist/rhel/server/6/6Server/x86_64/optional/os',
      'content/dist/rhel/server/6/6Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/oracle-java-rm/os',
      'content/dist/rhel/server/6/6Server/x86_64/oracle-java-rm/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/os',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/sap-hana/debug',
      'content/dist/rhel/server/6/6Server/x86_64/sap-hana/os',
      'content/dist/rhel/server/6/6Server/x86_64/sap-hana/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/sap/debug',
      'content/dist/rhel/server/6/6Server/x86_64/sap/os',
      'content/dist/rhel/server/6/6Server/x86_64/sap/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/os',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/supplementary/debug',
      'content/dist/rhel/server/6/6Server/x86_64/supplementary/os',
      'content/dist/rhel/server/6/6Server/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/oracle-java-rm/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/oracle-java-rm/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/supplementary/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/supplementary/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/oracle-java-rm/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/oracle-java-rm/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/supplementary/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/supplementary/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/supplementary/source/SRPMS',
      'content/els/rhel/server/6/6Server/i386/debug',
      'content/els/rhel/server/6/6Server/i386/optional/debug',
      'content/els/rhel/server/6/6Server/i386/optional/os',
      'content/els/rhel/server/6/6Server/i386/optional/source/SRPMS',
      'content/els/rhel/server/6/6Server/i386/os',
      'content/els/rhel/server/6/6Server/i386/source/SRPMS',
      'content/els/rhel/server/6/6Server/x86_64/debug',
      'content/els/rhel/server/6/6Server/x86_64/optional/debug',
      'content/els/rhel/server/6/6Server/x86_64/optional/os',
      'content/els/rhel/server/6/6Server/x86_64/optional/source/SRPMS',
      'content/els/rhel/server/6/6Server/x86_64/os',
      'content/els/rhel/server/6/6Server/x86_64/sap-hana/debug',
      'content/els/rhel/server/6/6Server/x86_64/sap-hana/os',
      'content/els/rhel/server/6/6Server/x86_64/sap-hana/source/SRPMS',
      'content/els/rhel/server/6/6Server/x86_64/sap/debug',
      'content/els/rhel/server/6/6Server/x86_64/sap/os',
      'content/els/rhel/server/6/6Server/x86_64/sap/source/SRPMS',
      'content/els/rhel/server/6/6Server/x86_64/source/SRPMS',
      'content/fastrack/rhel/client/6/i386/debug',
      'content/fastrack/rhel/client/6/i386/optional/debug',
      'content/fastrack/rhel/client/6/i386/optional/os',
      'content/fastrack/rhel/client/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/client/6/i386/os',
      'content/fastrack/rhel/client/6/i386/source/SRPMS',
      'content/fastrack/rhel/client/6/x86_64/debug',
      'content/fastrack/rhel/client/6/x86_64/optional/debug',
      'content/fastrack/rhel/client/6/x86_64/optional/os',
      'content/fastrack/rhel/client/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/client/6/x86_64/os',
      'content/fastrack/rhel/client/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/debug',
      'content/fastrack/rhel/computenode/6/x86_64/hpn/debug',
      'content/fastrack/rhel/computenode/6/x86_64/hpn/os',
      'content/fastrack/rhel/computenode/6/x86_64/hpn/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/optional/debug',
      'content/fastrack/rhel/computenode/6/x86_64/optional/os',
      'content/fastrack/rhel/computenode/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/os',
      'content/fastrack/rhel/computenode/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/computenode/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/computenode/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/debug',
      'content/fastrack/rhel/server/6/i386/highavailability/debug',
      'content/fastrack/rhel/server/6/i386/highavailability/os',
      'content/fastrack/rhel/server/6/i386/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/loadbalancer/debug',
      'content/fastrack/rhel/server/6/i386/loadbalancer/os',
      'content/fastrack/rhel/server/6/i386/loadbalancer/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/optional/debug',
      'content/fastrack/rhel/server/6/i386/optional/os',
      'content/fastrack/rhel/server/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/os',
      'content/fastrack/rhel/server/6/i386/resilientstorage/debug',
      'content/fastrack/rhel/server/6/i386/resilientstorage/os',
      'content/fastrack/rhel/server/6/i386/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/debug',
      'content/fastrack/rhel/server/6/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/6/x86_64/highavailability/os',
      'content/fastrack/rhel/server/6/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/hpn/debug',
      'content/fastrack/rhel/server/6/x86_64/hpn/os',
      'content/fastrack/rhel/server/6/x86_64/hpn/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/debug',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/os',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/optional/debug',
      'content/fastrack/rhel/server/6/x86_64/optional/os',
      'content/fastrack/rhel/server/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/os',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/workstation/6/i386/debug',
      'content/fastrack/rhel/workstation/6/i386/optional/debug',
      'content/fastrack/rhel/workstation/6/i386/optional/os',
      'content/fastrack/rhel/workstation/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/6/i386/os',
      'content/fastrack/rhel/workstation/6/i386/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/debug',
      'content/fastrack/rhel/workstation/6/x86_64/optional/debug',
      'content/fastrack/rhel/workstation/6/x86_64/optional/os',
      'content/fastrack/rhel/workstation/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/os',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'chromium-browser-83.0.4103.97-1.el6_10', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'chromium-browser-83.0.4103.97-1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromium-browser');
}
