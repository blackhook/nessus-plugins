#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2019:14163-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150681);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");

  script_cve_id("CVE-2019-10136");
  script_xref(name:"SuSE", value:"SUSE-SU-2019:14163-1");

  script_name(english:"SUSE SLES11 Security Update : SUSE Manager Client Tools (SUSE-SU-2019:14163-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by a vulnerability as referenced in the SUSE-
SU-2019:14163-1 advisory.

  - It was found that Spacewalk, all versions through 2.9, did not safely compute client token checksums. An
    attacker with a valid, but expired, authenticated set of headers could move some digits around,
    artificially extending the session validity without modifying the checksum. (CVE-2019-10136)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1103696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1104034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1130040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1135881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1136029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1136480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1137715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1137940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1138313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1138358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1138494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1138822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1139453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1142038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1143856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1144155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1144889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1148125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1148177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1148311");
  # https://lists.suse.com/pipermail/sle-security-updates/2019-September/005884.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73b295d6");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-10136");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10136");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-cfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-cfg-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-cfg-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-cfg-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-osad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-virtualization-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-cfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-cfg-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-cfg-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-cfg-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-osa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-osad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-virtualization-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-virtualization-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-rhnlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacecmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-remote-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'mgr-cfg-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-cfg-actions-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-cfg-client-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-cfg-management-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-daemon-4.0.7-5.8', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-osad-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-virtualization-host-4.0.8-5.8', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-cfg-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-cfg-actions-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-cfg-client-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-cfg-management-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-osa-common-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-osad-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-virtualization-common-4.0.8-5.8', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-virtualization-host-4.0.8-5.8', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-rhnlib-4.0.11-12.16', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'spacecmd-4.0.14-18.51', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'spacewalk-backend-libs-4.0.25-28.42', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'spacewalk-remote-utils-4.0.5-6.12', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-cfg-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-cfg-actions-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-cfg-client-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-cfg-management-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-daemon-4.0.7-5.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-osad-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-virtualization-host-4.0.8-5.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-cfg-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-cfg-actions-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-cfg-client-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-cfg-management-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-osa-common-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-osad-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-virtualization-common-4.0.8-5.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-virtualization-host-4.0.8-5.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-rhnlib-4.0.11-12.16', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'spacecmd-4.0.14-18.51', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'spacewalk-backend-libs-4.0.25-28.42', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'spacewalk-remote-utils-4.0.5-6.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-cfg-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-cfg-actions-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-cfg-client-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-cfg-management-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-daemon-4.0.7-5.8', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-osad-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-virtualization-host-4.0.8-5.8', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-cfg-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-cfg-actions-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-cfg-client-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-cfg-management-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-osa-common-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-osad-4.0.9-5.6', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-virtualization-common-4.0.8-5.8', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-virtualization-host-4.0.8-5.8', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-rhnlib-4.0.11-12.16', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'spacecmd-4.0.14-18.51', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'spacewalk-backend-libs-4.0.25-28.42', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'spacewalk-remote-utils-4.0.5-6.12', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-cfg-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mgr-cfg-actions-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mgr-cfg-client-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mgr-cfg-management-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mgr-daemon-4.0.7-5.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mgr-osad-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mgr-virtualization-host-4.0.8-5.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-cfg-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-cfg-actions-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-cfg-client-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-cfg-management-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-osa-common-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-osad-4.0.9-5.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-virtualization-common-4.0.8-5.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-virtualization-host-4.0.8-5.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-rhnlib-4.0.11-12.16', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'spacecmd-4.0.14-18.51', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'spacewalk-backend-libs-4.0.25-28.42', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'spacewalk-remote-utils-4.0.5-6.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mgr-cfg / mgr-cfg-actions / mgr-cfg-client / mgr-cfg-management / etc');
}
