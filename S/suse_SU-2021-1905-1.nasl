#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:1905-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150410);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/21");

  script_cve_id("CVE-2020-14355");
  script_xref(name:"SuSE", value:"SUSE-SU-2021:1905-1");

  script_name(english:"SUSE SLES12 Security Update : spice-gtk (SUSE-SU-2021:1905-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by a vulnerability as referenced in the SUSE-
SU-2021:1905-1 advisory.

  - Multiple buffer overflow vulnerabilities were found in the QUIC image decoding process of the SPICE remote
    display system, before spice-0.14.2-1. Both the SPICE client (spice-gtk) and server are affected by these
    flaws. These flaws allow a malicious client or server to send specially crafted messages that, when
    processed by the QUIC image compression algorithm, result in a process crash or potential code execution.
    (CVE-2020-14355)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177158");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2021-June/019242.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14355");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14355");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libspice-client-glib-2_0-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libspice-client-glib-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libspice-client-gtk-2_0-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libspice-client-gtk-3_0-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libspice-controller0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-SpiceClientGlib-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-SpiceClientGtk-3_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'libspice-client-glib-2_0-8-0.31-9.13', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.2'},
    {'reference':'libspice-client-glib-helper-0.31-9.13', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.2'},
    {'reference':'libspice-client-gtk-2_0-4-0.31-9.13', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.2'},
    {'reference':'libspice-client-gtk-3_0-4-0.31-9.13', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.2'},
    {'reference':'libspice-controller0-0.31-9.13', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.2'},
    {'reference':'typelib-1_0-SpiceClientGlib-2_0-0.31-9.13', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.2'},
    {'reference':'typelib-1_0-SpiceClientGtk-3_0-0.31-9.13', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.2'},
    {'reference':'libspice-client-glib-2_0-8-0.31-9.13', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'libspice-client-glib-helper-0.31-9.13', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'libspice-client-gtk-2_0-4-0.31-9.13', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'libspice-client-gtk-3_0-4-0.31-9.13', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'libspice-controller0-0.31-9.13', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'typelib-1_0-SpiceClientGlib-2_0-0.31-9.13', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'typelib-1_0-SpiceClientGtk-3_0-0.31-9.13', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libspice-client-glib-2_0-8 / libspice-client-glib-helper / etc');
}
