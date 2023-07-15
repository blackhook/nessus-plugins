#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:2125-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151742);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/04");

  script_cve_id(
    "CVE-2020-26418",
    "CVE-2020-26419",
    "CVE-2020-26420",
    "CVE-2020-26421",
    "CVE-2020-26422",
    "CVE-2021-22173",
    "CVE-2021-22174",
    "CVE-2021-22191",
    "CVE-2021-22207"
  );
  script_xref(name:"IAVB", value:"2021-B-0001-S");
  script_xref(name:"IAVB", value:"2021-B-0008-S");
  script_xref(name:"IAVB", value:"2021-B-0020-S");
  script_xref(name:"IAVB", value:"2021-B-0028-S");

  script_name(english:"openSUSE 15 Security Update : wireshark (openSUSE-SU-2021:2125-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:2125-1 advisory.

  - Memory leak in Kafka protocol dissector in Wireshark 3.4.0 and 3.2.0 to 3.2.8 allows denial of service via
    packet injection or crafted capture file. (CVE-2020-26418)

  - Memory leak in the dissection engine in Wireshark 3.4.0 allows denial of service via packet injection or
    crafted capture file. (CVE-2020-26419)

  - Memory leak in RTPS protocol dissector in Wireshark 3.4.0 and 3.2.0 to 3.2.8 allows denial of service via
    packet injection or crafted capture file. (CVE-2020-26420)

  - Crash in USB HID protocol dissector and possibly other dissectors in Wireshark 3.4.0 and 3.2.0 to 3.2.8
    allows denial of service via packet injection or crafted capture file. (CVE-2020-26421)

  - Buffer overflow in QUIC dissector in Wireshark 3.4.0 to 3.4.1 allows denial of service via packet
    injection or crafted capture file (CVE-2020-26422)

  - Memory leak in USB HID dissector in Wireshark 3.4.0 to 3.4.2 allows denial of service via packet injection
    or crafted capture file (CVE-2021-22173)

  - Crash in USB HID dissector in Wireshark 3.4.0 to 3.4.2 allows denial of service via packet injection or
    crafted capture file (CVE-2021-22174)

  - Improper URL handling in Wireshark 3.4.0 to 3.4.3 and 3.2.0 to 3.2.11 could allow remote code execution
    via via packet injection or crafted capture file. (CVE-2021-22191)

  - Excessive memory consumption in MS-WSP dissector in Wireshark 3.4.0 to 3.4.4 and 3.2.0 to 3.2.12 allows
    denial of service via packet injection or crafted capture file (CVE-2021-22207)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180102");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180232");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184110");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185128");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EZGXWOFRVD3EFRZ6YDAJZEVPBP7IUHFI/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f9c3342");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26418");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26419");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26420");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26421");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26422");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22173");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22174");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22191");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22207");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22191");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsbc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsbc1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwireshark14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwiretap11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsutil12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sbc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
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
    {'reference':'libsbc1-1.3-3.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsbc1-32bit-1.3-3.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwireshark14-3.4.5-3.53.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwiretap11-3.4.5-3.53.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwsutil12-3.4.5-3.53.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sbc-1.3-3.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sbc-devel-1.3-3.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wireshark-3.4.5-3.53.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wireshark-devel-3.4.5-3.53.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wireshark-ui-qt-3.4.5-3.53.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsbc1 / libsbc1-32bit / libwireshark14 / libwiretap11 / libwsutil12 / etc');
}
