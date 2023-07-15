#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1134-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152473);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-15999",
    "CVE-2020-35653",
    "CVE-2020-35654",
    "CVE-2020-35655",
    "CVE-2021-25289",
    "CVE-2021-25290",
    "CVE-2021-25291",
    "CVE-2021-25292",
    "CVE-2021-25293",
    "CVE-2021-27921",
    "CVE-2021-27922",
    "CVE-2021-27923",
    "CVE-2021-34552"
  );
  script_xref(name:"IAVA", value:"2020-A-0486-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2020-0124");

  script_name(english:"openSUSE 15 Security Update : python-CairoSVG, python-Pillow (openSUSE-SU-2021:1134-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1134-1 advisory.

  - Heap buffer overflow in Freetype in Google Chrome prior to 86.0.4240.111 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-15999)

  - In Pillow before 8.1.0, PcxDecode has a buffer over-read when decoding a crafted PCX file because the
    user-supplied stride value is trusted for buffer calculations. (CVE-2020-35653)

  - In Pillow before 8.1.0, TiffDecode has a heap-based buffer overflow when decoding crafted YCbCr files
    because of certain interpretation conflicts with LibTIFF in RGBA mode. (CVE-2020-35654)

  - In Pillow before 8.1.0, SGIRleDecode has a 4-byte buffer over-read when decoding crafted SGI RLE image
    files because offsets and length tables are mishandled. (CVE-2020-35655)

  - An issue was discovered in Pillow before 8.1.1. TiffDecode has a heap-based buffer overflow when decoding
    crafted YCbCr files because of certain interpretation conflicts with LibTIFF in RGBA mode. NOTE: this
    issue exists because of an incomplete fix for CVE-2020-35654. (CVE-2021-25289)

  - An issue was discovered in Pillow before 8.1.1. In TiffDecode.c, there is a negative-offset memcpy with an
    invalid size. (CVE-2021-25290)

  - An issue was discovered in Pillow before 8.1.1. In TiffDecode.c, there is an out-of-bounds read in
    TiffreadRGBATile via invalid tile boundaries. (CVE-2021-25291)

  - An issue was discovered in Pillow before 8.1.1. The PDF parser allows a regular expression DoS (ReDoS)
    attack via a crafted PDF file because of a catastrophic backtracking regex. (CVE-2021-25292)

  - An issue was discovered in Pillow before 8.1.1. There is an out-of-bounds read in SGIRleDecode.c.
    (CVE-2021-25293)

  - Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the
    reported size of a contained image is not properly checked for a BLP container, and thus an attempted
    memory allocation can be very large. (CVE-2021-27921)

  - Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the
    reported size of a contained image is not properly checked for an ICNS container, and thus an attempted
    memory allocation can be very large. (CVE-2021-27922)

  - Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the
    reported size of a contained image is not properly checked for an ICO container, and thus an attempted
    memory allocation can be very large. (CVE-2021-27923)

  - Pillow through 8.2.0 and PIL (aka Python Imaging Library) through 1.1.7 allow an attacker to pass
    controlled parameters directly into a convert function to trigger a buffer overflow in Convert.c.
    (CVE-2021-34552)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180833");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181281");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/N6MMS3NOFXF2TZBZ5M3EC6VOB65FRP4I/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27adf76a");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35654");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35655");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25289");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25291");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25292");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25293");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-34552");
  script_set_attribute(attribute:"solution", value:
"Update the affected python3-CairoSVG, python3-Pillow and / or python3-Pillow-tk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34552");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-CairoSVG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-Pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-Pillow-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'python3-CairoSVG-2.5.1-lp152.2.3.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-Pillow-8.3.1-lp152.5.3.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-Pillow-tk-8.3.1-lp152.5.3.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-CairoSVG / python3-Pillow / python3-Pillow-tk');
}
