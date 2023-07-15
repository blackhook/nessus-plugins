#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1641-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151685);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id(
    "CVE-2021-32490",
    "CVE-2021-32491",
    "CVE-2021-32492",
    "CVE-2021-32493"
  );

  script_name(english:"openSUSE 15 Security Update : djvulibre (openSUSE-SU-2021:1641-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1641-1 advisory.

  - A flaw was found in djvulibre-3.5.28 and earlier. An out of bounds write in function DJVU::filter_bv() via
    crafted djvu file may lead to application crash and other consequences. (CVE-2021-32490)

  - A flaw was found in djvulibre-3.5.28 and earlier. An integer overflow in function render() in tools/ddjvu
    via crafted djvu file may lead to application crash and other consequences. (CVE-2021-32491)

  - A flaw was found in djvulibre-3.5.28 and earlier. An out of bounds read in function
    DJVU::DataPool::has_data() via crafted djvu file may lead to application crash and other consequences.
    (CVE-2021-32492)

  - A flaw was found in djvulibre-3.5.28 and earlier. A heap buffer overflow in function
    DJVU::GBitmap::decode() via crafted djvu file may lead to application crash and other consequences.
    (CVE-2021-32493)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185905");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JR6UIBZP5PP63ZY663PXBSRRCYNCGVJV/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?323f5a90");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32490");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32491");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32492");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32493");
  script_set_attribute(attribute:"solution", value:
"Update the affected djvulibre, libdjvulibre-devel and / or libdjvulibre21 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32493");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:djvulibre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdjvulibre-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdjvulibre21");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
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
release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

pkgs = [
    {'reference':'djvulibre-3.5.27-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdjvulibre-devel-3.5.27-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdjvulibre21-3.5.27-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  rpm_spec_vers_cmp = NULL;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'djvulibre / libdjvulibre-devel / libdjvulibre21');
}
