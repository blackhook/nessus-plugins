#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1860-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151699);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id(
    "CVE-2018-25009",
    "CVE-2018-25010",
    "CVE-2018-25011",
    "CVE-2018-25012",
    "CVE-2018-25013",
    "CVE-2020-36328",
    "CVE-2020-36329",
    "CVE-2020-36330",
    "CVE-2020-36331",
    "CVE-2020-36332"
  );

  script_name(english:"openSUSE 15 Security Update : libwebp (openSUSE-SU-2021:1860-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1860-1 advisory.

  - A flaw was found in libwebp in versions before 1.0.1. An out-of-bounds read was found in function
    WebPMuxCreateInternal. The highest threat from this vulnerability is to data confidentiality and to the
    service availability. (CVE-2018-25009, CVE-2018-25012)

  - A flaw was found in libwebp in versions before 1.0.1. An out-of-bounds read was found in function
    ApplyFilter. The highest threat from this vulnerability is to data confidentiality and to the service
    availability. (CVE-2018-25010)

  - A flaw was found in libwebp in versions before 1.0.1. A heap-based buffer overflow was found in PutLE16().
    The highest threat from this vulnerability is to data confidentiality and integrity as well as system
    availability. (CVE-2018-25011)

  - A flaw was found in libwebp in versions before 1.0.1. An out-of-bounds read was found in function
    ShiftBytes. The highest threat from this vulnerability is to data confidentiality and to the service
    availability. (CVE-2018-25013)

  - A flaw was found in libwebp in versions before 1.0.1. A heap-based buffer overflow in function
    WebPDecodeRGBInto is possible due to an invalid check for buffer size. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability. (CVE-2020-36328)

  - A flaw was found in libwebp in versions before 1.0.1. A use-after-free was found due to a thread being
    killed too early. The highest threat from this vulnerability is to data confidentiality and integrity as
    well as system availability. (CVE-2020-36329)

  - A flaw was found in libwebp in versions before 1.0.1. An out-of-bounds read was found in function
    ChunkVerifyAndAssign. The highest threat from this vulnerability is to data confidentiality and to the
    service availability. (CVE-2020-36330)

  - A flaw was found in libwebp in versions before 1.0.1. An out-of-bounds read was found in function
    ChunkAssignData. The highest threat from this vulnerability is to data confidentiality and to the service
    availability. (CVE-2020-36331)

  - A flaw was found in libwebp in versions before 1.0.1. When reading a file libwebp allocates an excessive
    amount of memory. The highest threat from this vulnerability is to the service availability.
    (CVE-2020-36332)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186247");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4ZIJ3ZK5FGNGJN6E65XZKMQPSQ3RKNVG/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce547ea1");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-25009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-25010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-25011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-25012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-25013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36328");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36329");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36330");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36331");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36332");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36329");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebp6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebp6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebpdecoder2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebpdecoder2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebpextras0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebpextras0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebpmux2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebpmux2-32bit");
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
    {'reference':'libwebp6-0.5.0-3.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebp6-32bit-0.5.0-3.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebpdecoder2-0.5.0-3.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebpdecoder2-32bit-0.5.0-3.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebpextras0-0.5.0-3.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebpextras0-32bit-0.5.0-3.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebpmux2-0.5.0-3.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebpmux2-32bit-0.5.0-3.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libwebp6 / libwebp6-32bit / libwebpdecoder2 / libwebpdecoder2-32bit / etc');
}
