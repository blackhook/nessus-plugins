#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:2793-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152725);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/22");

  script_cve_id(
    "CVE-2021-3476",
    "CVE-2021-20298",
    "CVE-2021-20299",
    "CVE-2021-20300",
    "CVE-2021-20302",
    "CVE-2021-20303",
    "CVE-2021-20304"
  );

  script_name(english:"openSUSE 15 Security Update : openexr (openSUSE-SU-2021:2793-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:2793-1 advisory.

  - A flaw found in function dataWindowForTile() of IlmImf/ImfTiledMisc.cpp. An attacker who is able to submit
    a crafted file to be processed by OpenEXR could trigger an integer overflow, leading to an out-of-bounds
    write on the heap. The greatest impact of this flaw is to application availability, with some potential
    impact to data integrity as well. (CVE-2021-20303)

  - A flaw was found in OpenEXR's B44 uncompression functionality in versions before 3.0.0-beta. An attacker
    who is able to submit a crafted file to OpenEXR could trigger shift overflows, potentially affecting
    application availability. (CVE-2021-3476)

  - A flaw was found in OpenEXR's Multipart input file functionality. A crafted multi-part input file with no
    actual parts can trigger a NULL pointer dereference. The highest threat from this vulnerability is to
    system availability. (CVE-2021-20299)

  - A flaw was found in OpenEXR's hufUncompress functionality in OpenEXR/IlmImf/ImfHuf.cpp. This flaw allows
    an attacker who can submit a crafted file that is processed by OpenEXR, to trigger an integer overflow.
    The highest threat from this vulnerability is to system availability. (CVE-2021-20300)

  - A flaw was found in OpenEXR's TiledInputFile functionality. This flaw allows an attacker who can submit a
    crafted single-part non-image to be processed by OpenEXR, to trigger a floating-point exception error. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20302)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188460");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188462");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/I6OVSOAQ3PQXBTM46SMNT6H3XP45CC7L/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3255e7b0");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20298");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20299");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20300");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20302");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20303");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20304");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3476");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20303");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libIlmImf-2_2-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libIlmImf-2_2-23-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libIlmImfUtil-2_2-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libIlmImfUtil-2_2-23-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openexr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openexr-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
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
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'libIlmImf-2_2-23-2.2.1-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libIlmImf-2_2-23-32bit-2.2.1-3.35.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libIlmImfUtil-2_2-23-2.2.1-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libIlmImfUtil-2_2-23-32bit-2.2.1-3.35.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openexr-2.2.1-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openexr-devel-2.2.1-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libIlmImf-2_2-23 / libIlmImf-2_2-23-32bit / libIlmImfUtil-2_2-23 / etc');
}
