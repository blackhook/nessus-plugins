#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2022-1854.
##

include('compat.inc');

if (description)
{
  script_id(165993);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/11");

  script_cve_id(
    "CVE-2019-3842",
    "CVE-2020-13529",
    "CVE-2020-13776",
    "CVE-2022-2526"
  );

  script_name(english:"Amazon Linux 2 : systemd (ALAS-2022-1854)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of systemd installed on the remote host is prior to 219-78. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2022-1854 advisory.

  - In systemd before v242-rc4, it was discovered that pam_systemd does not properly sanitize the environment
    before using the XDG_SEAT variable. It is possible for an attacker, in some particular configurations, to
    set a XDG_SEAT environment variable which allows for commands to be checked against polkit policies using
    the allow_active element rather than allow_any. (CVE-2019-3842)

  - An exploitable denial-of-service vulnerability exists in Systemd 245. A specially crafted DHCP FORCERENEW
    packet can cause a server running the DHCP client to be vulnerable to a DHCP ACK spoofing attack. An
    attacker can forge a pair of FORCERENEW and DCHP ACK packets to reconfigure the server. (CVE-2020-13529)

  - systemd through v245 mishandles numerical usernames such as ones composed of decimal digits or 0x followed
    by hex digits, as demonstrated by use of root privileges when privileges of the 0x0 user account were
    intended. NOTE: this issue exists because of an incomplete fix for CVE-2017-1000082. (CVE-2020-13776)

  - A use-after-free vulnerability was found in systemd. This issue occurs due to the on_stream_io() function
    and dns_stream_complete() function in 'resolved-dns-stream.c' not incrementing the reference counting for
    the DnsStream object. Therefore, other functions and callbacks called can dereference the DNSStream
    object, causing the use-after-free when the reference is still used later. (CVE-2022-2526)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2022-1854.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-3842.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-13529.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-13776.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2526.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update systemd' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13776");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2526");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgudev1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-journal-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-networkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-resolved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'libgudev1-219-78.amzn2.0.20', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-219-78.amzn2.0.20', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-219-78.amzn2.0.20', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-devel-219-78.amzn2.0.20', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-devel-219-78.amzn2.0.20', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-devel-219-78.amzn2.0.20', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-219-78.amzn2.0.20', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-219-78.amzn2.0.20', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-219-78.amzn2.0.20', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-debuginfo-219-78.amzn2.0.20', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-debuginfo-219-78.amzn2.0.20', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-debuginfo-219-78.amzn2.0.20', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-219-78.amzn2.0.20', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-219-78.amzn2.0.20', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-219-78.amzn2.0.20', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-gateway-219-78.amzn2.0.20', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-gateway-219-78.amzn2.0.20', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-gateway-219-78.amzn2.0.20', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-219-78.amzn2.0.20', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-219-78.amzn2.0.20', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-219-78.amzn2.0.20', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-networkd-219-78.amzn2.0.20', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-networkd-219-78.amzn2.0.20', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-networkd-219-78.amzn2.0.20', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-python-219-78.amzn2.0.20', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-python-219-78.amzn2.0.20', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-python-219-78.amzn2.0.20', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-resolved-219-78.amzn2.0.20', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-resolved-219-78.amzn2.0.20', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-resolved-219-78.amzn2.0.20', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-sysv-219-78.amzn2.0.20', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-sysv-219-78.amzn2.0.20', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-sysv-219-78.amzn2.0.20', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgudev1 / libgudev1-devel / systemd / etc");
}