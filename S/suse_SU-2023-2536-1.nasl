#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2536-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(177439);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/22");

  script_cve_id("CVE-2023-1668");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2536-1");

  script_name(english:"SUSE SLES15 Security Update : openvswitch3 (SUSE-SU-2023:2536-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by a vulnerability as referenced in the SUSE-
SU-2023:2536-1 advisory.

  - A flaw was found in openvswitch (OVS). When processing an IP packet with protocol 0, OVS will install the
    datapath flow without the action modifying the IP header. This issue results (for both kernel and
    userspace datapath) in installing a datapath flow matching all IP protocols (nw_proto is wildcarded) for
    this flow, but with an incorrect action, possibly causing incorrect handling of other IP packets with a !=
    0 IP protocol that matches this dp flow. (CVE-2023-1668)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210054");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-June/029920.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1668");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1668");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenvswitch-3_1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libovn-23_03-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch3-ipsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch3-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch3-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch3-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ovn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ovn3-central");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ovn3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ovn3-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ovn3-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ovn3-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ovs3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libopenvswitch-3_1-0-3.1.0-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'libovn-23_03-0-23.03.0-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'openvswitch3-3.1.0-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'openvswitch3-devel-3.1.0-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'openvswitch3-ipsec-3.1.0-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'openvswitch3-pki-3.1.0-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'openvswitch3-test-3.1.0-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'openvswitch3-vtep-3.1.0-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'ovn3-23.03.0-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'ovn3-central-23.03.0-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'ovn3-devel-23.03.0-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'ovn3-docker-23.03.0-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'ovn3-host-23.03.0-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'ovn3-vtep-23.03.0-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'python3-ovs3-3.1.0-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'libopenvswitch-3_1-0-3.1.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libovn-23_03-0-23.03.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'openvswitch3-3.1.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'openvswitch3-devel-3.1.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'openvswitch3-doc-3.1.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'openvswitch3-ipsec-3.1.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'openvswitch3-pki-3.1.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'openvswitch3-test-3.1.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'openvswitch3-vtep-3.1.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ovn3-23.03.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ovn3-central-23.03.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ovn3-devel-23.03.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ovn3-doc-23.03.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ovn3-docker-23.03.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ovn3-host-23.03.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ovn3-vtep-23.03.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python3-ovs3-3.1.0-150500.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenvswitch-3_1-0 / libovn-23_03-0 / openvswitch3 / etc');
}
