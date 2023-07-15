#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2022-1856.
##

include('compat.inc');

if (description)
{
  script_id(165997);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/29");

  script_cve_id("CVE-2022-2319", "CVE-2022-2320");

  script_name(english:"Amazon Linux 2 : xorg-x11-server (ALAS-2022-1856)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2-2022-1856 advisory.

  - A flaw was found in the Xorg-x11-server. An out-of-bounds access issue can occur in the ProcXkbSetGeometry
    function due to improper validation of the request length. (CVE-2022-2319)

  - A flaw was found in the Xorg-x11-server. The specific flaw exists within the handling of
    ProcXkbSetDeviceInfo requests. The issue results from the lack of proper validation of user-supplied data,
    which can result in a memory access past the end of an allocated buffer. This flaw allows an attacker to
    escalate privileges and execute arbitrary code in the context of root. (CVE-2022-2320)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2022-1856.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2319.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2320.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update xorg-x11-server' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2320");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-source");
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
    {'reference':'xorg-x11-server-common-1.20.4-18.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-common-1.20.4-18.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-common-1.20.4-18.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-debuginfo-1.20.4-18.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-debuginfo-1.20.4-18.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-debuginfo-1.20.4-18.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-devel-1.20.4-18.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-devel-1.20.4-18.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-devel-1.20.4-18.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-source-1.20.4-18.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xdmx-1.20.4-18.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xdmx-1.20.4-18.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xdmx-1.20.4-18.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xephyr-1.20.4-18.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xephyr-1.20.4-18.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xephyr-1.20.4-18.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xnest-1.20.4-18.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xnest-1.20.4-18.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xnest-1.20.4-18.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xorg-1.20.4-18.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xorg-1.20.4-18.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xorg-1.20.4-18.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xvfb-1.20.4-18.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xvfb-1.20.4-18.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xvfb-1.20.4-18.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xwayland-1.20.4-18.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xwayland-1.20.4-18.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xwayland-1.20.4-18.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server-Xdmx / xorg-x11-server-Xephyr / xorg-x11-server-Xnest / etc");
}