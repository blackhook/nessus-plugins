#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:1580-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(173448);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id("CVE-2022-0670", "CVE-2022-3650", "CVE-2022-3854");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:1580-1");

  script_name(english:"SUSE SLES15 Security Update : ceph (SUSE-SU-2023:1580-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2023:1580-1 advisory.

  - A flaw was found in Openstack manilla owning a Ceph File system share, which enables the owner to
    read/write any manilla share or entire file system. The vulnerability is due to a bug in the volumes
    plugin in Ceph Manager. This allows an attacker to compromise Confidentiality and Integrity of a file
    system. Fixed in RHCS 5.2 and Ceph 17.2.2. (CVE-2022-0670)

  - A privilege escalation flaw was found in Ceph. Ceph-crash.service allows a local attacker to escalate
    privileges to root in the form of a crash dump, and dump privileged information. (CVE-2022-3650)

  - A flaw was found in Ceph, relating to the URL processing on RGW backends. An attacker can exploit the URL
    processing by providing a null URL to crash the RGW, causing a denial of service. (CVE-2022-3854)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206158");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-March/028381.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3854");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0670");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libradospp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rados-objclass-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-nbd");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'ceph-common-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'libcephfs-devel-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'libcephfs2-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'librados-devel-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'librados2-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'libradospp-devel-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'librbd-devel-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'librbd1-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'librgw-devel-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'librgw2-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'python3-ceph-argparse-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'python3-ceph-common-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'python3-cephfs-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'python3-rados-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'python3-rbd-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'python3-rgw-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'rados-objclass-devel-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'rbd-nbd-16.2.11.58+g38d6afd3b78-150300.5.7.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph-common / libcephfs-devel / libcephfs2 / librados-devel / etc');
}
