#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-154.
##

include('compat.inc');

if (description)
{
  script_id(173858);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id(
    "CVE-2022-3647",
    "CVE-2022-35977",
    "CVE-2022-36021",
    "CVE-2023-25155"
  );

  script_name(english:"Amazon Linux 2023 : redis6, redis6-devel (ALAS2023-2023-154)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-154 advisory.

  - Redis is an in-memory database that persists on disk. Authenticated users issuing specially crafted
    `SETRANGE` and `SORT(_RO)` commands can trigger an integer overflow, resulting with Redis attempting to
    allocate impossible amounts of memory and abort with an out-of-memory (OOM) panic. The problem is fixed in
    Redis versions 7.0.8, 6.2.9 and 6.0.17. Users are advised to upgrade. There are no known workarounds for
    this vulnerability. (CVE-2022-35977)

  - Redis is an in-memory database that persists on disk. Authenticated users can use string matching commands
    (like `SCAN` or `KEYS`) with a specially crafted pattern to trigger a denial-of-service attack on Redis,
    causing it to hang and consume 100% CPU time. The problem is fixed in Redis versions 6.0.18, 6.2.11,
    7.0.9. (CVE-2022-36021)

  - ** DISPUTED ** A vulnerability, which was classified as problematic, was found in Redis. Affected is the
    function sigsegvHandler of the file debug.c of the component Crash Report. The manipulation leads to
    denial of service. The real existence of this vulnerability is still doubted at the moment. The name of
    the patch is 0bf90d944313919eb8e63d3588bf63a367f020a3. It is recommended to apply a patch to fix this
    issue. VDB-211962 is the identifier assigned to this vulnerability. NOTE: The vendor claims that this is
    not a DoS because it applies to the crash logging mechanism which is triggered after a crash has occurred.
    (CVE-2022-3647)

  - Redis is an in-memory database that persists on disk. Authenticated users issuing specially crafted
    `SRANDMEMBER`, `ZRANDMEMBER`, and `HRANDFIELD` commands can trigger an integer overflow, resulting in a
    runtime assertion and termination of the Redis server process. This problem affects all Redis versions.
    Patches were released in Redis version(s) 6.0.18, 6.2.11 and 7.0.9. (CVE-2023-25155)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-154.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-35977.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-36021.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3647.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-25155.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update redis6 --releasever=2023.0.20230329' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25155");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:redis6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:redis6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:redis6-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:redis6-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:redis6-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'redis6-6.2.11-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'redis6-6.2.11-1.amzn2023.0.1', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'redis6-6.2.11-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'redis6-debuginfo-6.2.11-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'redis6-debuginfo-6.2.11-1.amzn2023.0.1', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'redis6-debuginfo-6.2.11-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'redis6-debugsource-6.2.11-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'redis6-debugsource-6.2.11-1.amzn2023.0.1', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'redis6-debugsource-6.2.11-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'redis6-devel-6.2.11-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'redis6-devel-6.2.11-1.amzn2023.0.1', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'redis6-devel-6.2.11-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'redis6-doc-6.2.11-1.amzn2023.0.1', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "redis6 / redis6-debuginfo / redis6-debugsource / etc");
}