#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3938-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155894);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/30");

  script_cve_id(
    "CVE-2021-39920",
    "CVE-2021-39921",
    "CVE-2021-39922",
    "CVE-2021-39924",
    "CVE-2021-39925",
    "CVE-2021-39926",
    "CVE-2021-39928",
    "CVE-2021-39929"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3938-1");
  script_xref(name:"IAVB", value:"2021-B-0065-S");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : wireshark (SUSE-SU-2021:3938-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2021:3938-1 advisory.

  - NULL pointer exception in the IPPUSB dissector in Wireshark 3.4.0 to 3.4.9 allows denial of service via
    packet injection or crafted capture file (CVE-2021-39920)

  - NULL pointer exception in the Modbus dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows
    denial of service via packet injection or crafted capture file (CVE-2021-39921)

  - Buffer overflow in the C12.22 dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows denial of
    service via packet injection or crafted capture file (CVE-2021-39922)

  - Large loop in the Bluetooth DHT dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows denial of
    service via packet injection or crafted capture file (CVE-2021-39924)

  - Buffer overflow in the Bluetooth SDP dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows
    denial of service via packet injection or crafted capture file (CVE-2021-39925)

  - Buffer overflow in the Bluetooth HCI_ISO dissector in Wireshark 3.4.0 to 3.4.9 allows denial of service
    via packet injection or crafted capture file (CVE-2021-39926)

  - NULL pointer exception in the IEEE 802.11 dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows
    denial of service via packet injection or crafted capture file (CVE-2021-39928)

  - Uncontrolled Recursion in the Bluetooth DHT dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17
    allows denial of service via packet injection or crafted capture file (CVE-2021-39929)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192830");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-December/009860.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa12ecc6");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39929");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39929");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwireshark14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwiretap11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwsutil12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-ui-qt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'libwireshark14-3.4.10-3.62.1', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.2'},
    {'reference':'libwireshark14-3.4.10-3.62.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.2'},
    {'reference':'libwiretap11-3.4.10-3.62.1', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.2'},
    {'reference':'libwiretap11-3.4.10-3.62.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.2'},
    {'reference':'libwsutil12-3.4.10-3.62.1', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.2'},
    {'reference':'libwsutil12-3.4.10-3.62.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.2'},
    {'reference':'wireshark-3.4.10-3.62.1', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.2'},
    {'reference':'wireshark-3.4.10-3.62.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.2'},
    {'reference':'libwireshark14-3.4.10-3.62.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libwireshark14-3.4.10-3.62.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libwiretap11-3.4.10-3.62.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libwiretap11-3.4.10-3.62.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libwsutil12-3.4.10-3.62.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libwsutil12-3.4.10-3.62.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'wireshark-3.4.10-3.62.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'wireshark-3.4.10-3.62.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'wireshark-devel-3.4.10-3.62.1', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'wireshark-devel-3.4.10-3.62.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'wireshark-ui-qt-3.4.10-3.62.1', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'wireshark-ui-qt-3.4.10-3.62.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'wireshark-devel-3.4.10-3.62.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'wireshark-devel-3.4.10-3.62.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'wireshark-ui-qt-3.4.10-3.62.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'wireshark-ui-qt-3.4.10-3.62.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libwireshark14 / libwiretap11 / libwsutil12 / wireshark / etc');
}
