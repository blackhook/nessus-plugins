#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:1065-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159455);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/01");

  script_cve_id(
    "CVE-2021-0066",
    "CVE-2021-0071",
    "CVE-2021-0072",
    "CVE-2021-0076",
    "CVE-2021-0161",
    "CVE-2021-0164",
    "CVE-2021-0165",
    "CVE-2021-0166",
    "CVE-2021-0168",
    "CVE-2021-0170",
    "CVE-2021-0172",
    "CVE-2021-0173",
    "CVE-2021-0174",
    "CVE-2021-0175",
    "CVE-2021-0176",
    "CVE-2021-0183",
    "CVE-2021-33139",
    "CVE-2021-33155"
  );

  script_name(english:"openSUSE 15 Security Update : kernel-firmware (openSUSE-SU-2022:1065-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:1065-1 advisory.

  - Improper input validation in firmware for Intel(R) PROSet/Wireless Wi-Fi in multiple operating systems and
    Killer(TM) Wi-Fi in Windows 10 and 11 may allow an unauthenticated user to potentially enable escalation
    of privilege via local access. (CVE-2021-0066)

  - Improper input validation in firmware for some Intel(R) PROSet/Wireless WiFi in UEFI may allow an
    unauthenticated user to potentially enable escalation of privilege via adjacent access. (CVE-2021-0071)

  - Improper input validation in firmware for some Intel(R) PROSet/Wireless Wi-Fi in multiple operating
    systems and some Killer(TM) Wi-Fi in Windows 10 and 11 may allow a privileged user to potentially enable
    information disclosure via local access. (CVE-2021-0072)

  - Improper Validation of Specified Index, Position, or Offset in Input in firmware for some Intel(R)
    PROSet/Wireless Wi-Fi in multiple operating systems and some Killer(TM) Wi-Fi in Windows 10 and 11 may
    allow a privileged user to potentially enable denial of service via local access. (CVE-2021-0076)

  - Improper input validation in firmware for Intel(R) PROSet/Wireless Wi-Fi in multiple operating systems and
    Killer(TM) Wi-Fi in Windows 10 and 11 may allow a privileged user to potentially enable escalation of
    privilege via local access. (CVE-2021-0161)

  - Improper access control in firmware for Intel(R) PROSet/Wireless Wi-Fi in multiple operating systems and
    Killer(TM) Wi-Fi in Windows 10 and 11 may allow an unauthenticated user to potentially enable escalation
    of privilege via local access. (CVE-2021-0164)

  - Improper input validation in firmware for Intel(R) PROSet/Wireless Wi-Fi in multiple operating systems and
    Killer(TM) Wi-Fi in Windows 10 and 11 may allow an unauthenticated user to potentially enable denial of
    service via adjacent access. (CVE-2021-0165)

  - Exposure of Sensitive Information to an Unauthorized Actor in firmware for some Intel(R) PROSet/Wireless
    Wi-Fi in multiple operating systems and some Killer(TM) Wi-Fi in Windows 10 and 11 may allow a privileged
    user to potentially enable escalation of privilege via local access. (CVE-2021-0166)

  - Improper input validation in firmware for some Intel(R) PROSet/Wireless Wi-Fi in multiple operating
    systems and some Killer(TM) Wi-Fi in Windows 10 and 11 may allow a privileged user to potentially enable
    escalation of privilege via local access. (CVE-2021-0168)

  - Exposure of Sensitive Information to an Unauthorized Actor in firmware for some Intel(R) PROSet/Wireless
    Wi-Fi in multiple operating systems and some Killer(TM) Wi-Fi in Windows 10 and 11 may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2021-0170)

  - Improper input validation in firmware for some Intel(R) PROSet/Wireless Wi-Fi in multiple operating
    systems and some Killer(TM) Wi-Fi in Windows 10 and 11 may allow an unauthenticated user to potentially
    enable denial of service via adjacent access. (CVE-2021-0172)

  - Improper Validation of Consistency within input in firmware for some Intel(R) PROSet/Wireless Wi-Fi in
    multiple operating systems and some Killer(TM) Wi-Fi in Windows 10 and 11 may allow a unauthenticated user
    to potentially enable denial of service via adjacent access. (CVE-2021-0173)

  - Improper Use of Validation Framework in firmware for some Intel(R) PROSet/Wireless Wi-Fi in multiple
    operating systems and some Killer(TM) Wi-Fi in Windows 10 and 11 may allow a unauthenticated user to
    potentially enable denial of service via adjacent access. (CVE-2021-0174)

  - Improper Validation of Specified Index, Position, or Offset in Input in firmware for some Intel(R)
    PROSet/Wireless Wi-Fi in multiple operating systems and some Killer(TM) Wi-Fi in Windows 10 and 11 may
    allow an unauthenticated user to potentially enable denial of service via adjacent access. (CVE-2021-0175)

  - Improper input validation in firmware for some Intel(R) PROSet/Wireless Wi-Fi in multiple operating
    systems and some Killer(TM) Wi-Fi in Windows 10 and 11 may allow a privileged user to potentially enable
    denial of service via local access. (CVE-2021-0176)

  - Improper Validation of Specified Index, Position, or Offset in Input in software for some Intel(R)
    PROSet/Wireless Wi-Fi in multiple operating systems and some Killer(TM) Wi-Fi in Windows 10 and 11 may
    allow an unauthenticated user to potentially enable denial of service via adjacent access. (CVE-2021-0183)

  - Improper conditions check in firmware for some Intel(R) Wireless Bluetooth(R) and Killer(TM) Bluetooth(R)
    products before version 22.100 may allow an authenticated user to potentially enable denial of service via
    adjacent access. (CVE-2021-33139)

  - Improper input validation in firmware for some Intel(R) Wireless Bluetooth(R) and Killer(TM) Bluetooth(R)
    products before version 22.100 may allow an authenticated user to potentially enable denial of service via
    adjacent access. (CVE-2021-33155)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196333");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QNS2QRVZ2MWL6BB6UKZX6H5IFTGR7LZ2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3871a848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0066");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0071");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0072");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0161");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0164");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0165");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0168");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0170");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0172");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0173");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0174");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0175");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0176");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0183");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33139");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33155");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0071");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-amdgpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-ath10k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-ath11k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-atheros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-bnx2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-brcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-chelsio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-dpaa2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-i915");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-iwlwifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-liquidio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-media");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-mediatek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-mellanox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-mwifiex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-nfp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-platform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-prestera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-qlogic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-radeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-realtek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-serial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-sound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-ti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-ueagle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware-usb-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ucode-amd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


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
    {'reference':'kernel-firmware-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-all-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-amdgpu-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-ath10k-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-ath11k-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-atheros-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-bluetooth-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-bnx2-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-brcm-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-chelsio-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-dpaa2-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-i915-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-intel-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-iwlwifi-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-liquidio-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-marvell-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-media-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-mediatek-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-mellanox-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-mwifiex-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-network-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-nfp-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-nvidia-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-platform-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-prestera-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-qlogic-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-radeon-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-realtek-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-serial-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-sound-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-ti-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-ueagle-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-firmware-usb-network-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ucode-amd-20210208-150300.4.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-firmware / kernel-firmware-all / kernel-firmware-amdgpu / etc');
}
