#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0070-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158639);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2021-30625",
    "CVE-2021-30626",
    "CVE-2021-30627",
    "CVE-2021-30628",
    "CVE-2021-30630",
    "CVE-2021-30631",
    "CVE-2021-30632",
    "CVE-2021-30633",
    "CVE-2021-37981",
    "CVE-2021-37984",
    "CVE-2021-37987",
    "CVE-2021-37989",
    "CVE-2021-37992",
    "CVE-2021-37996",
    "CVE-2021-37998",
    "CVE-2021-38001",
    "CVE-2021-38002",
    "CVE-2021-38003"
  );
  script_xref(name:"IAVA", value:"2021-A-0411-S");
  script_xref(name:"IAVA", value:"2021-A-0491-S");
  script_xref(name:"IAVA", value:"2021-A-0522-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"openSUSE 15 Security Update : nodejs-electron (openSUSE-SU-2022:0070-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0070-1 advisory.

  - Use after free in Selection API in Google Chrome prior to 93.0.4577.82 allowed a remote attacker who
    convinced the user the visit a malicious website to potentially exploit heap corruption via a crafted HTML
    page. (CVE-2021-30625)

  - Out of bounds memory access in ANGLE in Google Chrome prior to 93.0.4577.82 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30626)

  - Type confusion in Blink layout in Google Chrome prior to 93.0.4577.82 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30627)

  - Stack buffer overflow in ANGLE in Google Chrome prior to 93.0.4577.82 allowed a remote attacker to
    potentially exploit stack corruption via a crafted HTML page. (CVE-2021-30628)

  - Inappropriate implementation in Blink in Google Chrome prior to 93.0.4577.82 allowed a remote attacker who
    had compromised the renderer process to leak cross-origin data via a crafted HTML page. (CVE-2021-30630)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by
    its CNA. Further investigation showed that it was not a security issue. Notes: none. (CVE-2021-30631)

  - Out of bounds write in V8 in Google Chrome prior to 93.0.4577.82 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-30632)

  - Use after free in Indexed DB API in Google Chrome prior to 93.0.4577.82 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2021-30633)

  - Heap buffer overflow in Skia in Google Chrome prior to 95.0.4638.54 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2021-37981)

  - Heap buffer overflow in PDFium in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37984)

  - Use after free in Network APIs in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37987)

  - Inappropriate implementation in Blink in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to
    abuse content security policy via a crafted HTML page. (CVE-2021-37989)

  - Out of bounds read in WebAudio in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37992)

  - Insufficient validation of untrusted input Downloads in Google Chrome prior to 95.0.4638.54 allowed a
    remote attacker to bypass navigation restrictions via a malicious file. (CVE-2021-37996)

  - Use after free in Garbage Collection in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37998)

  - Type confusion in V8 in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-38001)

  - Use after free in Web Transport in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to
    potentially perform a sandbox escape via a crafted HTML page. (CVE-2021-38002)

  - Inappropriate implementation in V8 in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-38003)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/G2JZKFAH5MWINMQLTSYZ2GQCLX5UGIGE/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09a3d8c4");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30625");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30626");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30627");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30630");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30632");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37987");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37992");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38003");
  script_set_attribute(attribute:"solution", value:
"Update the affected nodejs-electron and / or nodejs-electron-devel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38003");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-38002");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-electron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-electron-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'nodejs-electron-16.0.9-bp153.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-electron-devel-16.0.9-bp153.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs-electron / nodejs-electron-devel');
}
