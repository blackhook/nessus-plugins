##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2021-d9faeff8eb
#

include('compat.inc');

if (description)
{
  script_id(145388);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/12");

  script_cve_id(
    "CVE-2020-15995",
    "CVE-2020-16043",
    "CVE-2021-21106",
    "CVE-2021-21107",
    "CVE-2021-21108",
    "CVE-2021-21109",
    "CVE-2021-21110",
    "CVE-2021-21111",
    "CVE-2021-21112",
    "CVE-2021-21113",
    "CVE-2021-21114",
    "CVE-2021-21115",
    "CVE-2021-21116"
  );
  script_xref(name:"FEDORA", value:"2021-d9faeff8eb");

  script_name(english:"Fedora 32 : chromium (2021-d9faeff8eb)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 32 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2021-d9faeff8eb advisory.

  - Out of bounds write in V8 in Google Chrome prior to 86.0.4240.99 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-15995)

  - Insufficient data validation in networking in Google Chrome prior to 87.0.4280.141 allowed a remote
    attacker to bypass discretionary access control via malicious network traffic. (CVE-2020-16043)

  - Use after free in autofill in Google Chrome prior to 87.0.4280.141 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2021-21106)

  - Use after free in drag and drop in Google Chrome on Linux prior to 87.0.4280.141 allowed a remote attacker
    who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2021-21107)

  - Use after free in media in Google Chrome prior to 87.0.4280.141 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2021-21108)

  - Use after free in payments in Google Chrome prior to 87.0.4280.141 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2021-21109)

  - Use after free in safe browsing in Google Chrome prior to 87.0.4280.141 allowed a remote attacker to
    potentially perform a sandbox escape via a crafted HTML page. (CVE-2021-21110)

  - Insufficient policy enforcement in WebUI in Google Chrome prior to 87.0.4280.141 allowed an attacker who
    convinced a user to install a malicious extension to potentially perform a sandbox escape via a crafted
    Chrome Extension. (CVE-2021-21111)

  - Use after free in Blink in Google Chrome prior to 87.0.4280.141 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-21112)

  - Heap buffer overflow in Skia in Google Chrome prior to 87.0.4280.141 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-21113)

  - Use after free in audio in Google Chrome prior to 87.0.4280.141 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-21114)

  - User after free in safe browsing in Google Chrome prior to 87.0.4280.141 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2021-21115)

  - Heap buffer overflow in audio in Google Chrome prior to 87.0.4280.141 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-21116)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2021-d9faeff8eb");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21106");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromium");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Fedora' >!< release) audit(AUDIT_OS_NOT, 'Fedora');
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^32([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 32', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

pkgs = [
    {'reference':'chromium-87.0.4280.141-1.fc32', 'release':'FC32', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromium');
}
