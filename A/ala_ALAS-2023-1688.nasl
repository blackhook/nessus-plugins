#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2023-1688.
##

include('compat.inc');

if (description)
{
  script_id(171855);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2021-3772",
    "CVE-2021-4002",
    "CVE-2021-4155",
    "CVE-2021-20322",
    "CVE-2021-28711",
    "CVE-2021-28712",
    "CVE-2021-28713",
    "CVE-2021-28714",
    "CVE-2021-28715"
  );

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2023-1688)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 4.14.262-135.486. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS-2023-1688 advisory.

  - A flaw in the processing of received ICMP errors (ICMP fragment needed and ICMP redirect) in the Linux
    kernel functionality was found to allow the ability to quickly scan open UDP ports. This flaw allows an
    off-path remote user to effectively bypass the source port UDP randomization. The highest threat from this
    vulnerability is to confidentiality and possibly integrity, because software that relies on UDP source
    port randomization are indirectly affected as well. (CVE-2021-20322)

  - Rogue backends can cause DoS of guests via high frequency events T[his CNA information record relates to
    multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Xen offers the
    ability to run PV backends in regular unprivileged guests, typically referred to as driver domains.
    Running PV backends in driver domains has one primary security advantage: if a driver domain gets
    compromised, it doesn't have the privileges to take over the system. However, a malicious driver domain
    could try to attack other guests via sending events at a high frequency leading to a Denial of Service in
    the guest due to trying to service interrupts for elongated amounts of time. There are three affected
    backends: * blkfront patch 1, CVE-2021-28711 * netfront patch 2, CVE-2021-28712 * hvc_xen (console) patch
    3, CVE-2021-28713 (CVE-2021-28711, CVE-2021-28712, CVE-2021-28713)

  - Guest can force Linux netback driver to hog large amounts of kernel memory T[his CNA information record
    relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.]
    Incoming data packets for a guest in the Linux kernel's netback driver are buffered until the guest is
    ready to process them. There are some measures taken for avoiding to pile up too much data, but those can
    be bypassed by the guest: There is a timeout how long the client side of an interface can stop consuming
    new packets before it is assumed to have stalled, but this timeout is rather long (60 seconds by default).
    Using a UDP connection on a fast interface can easily accumulate gigabytes of data in that time.
    (CVE-2021-28715) The timeout could even never trigger if the guest manages to have only one free slot in
    its RX queue ring page and the next package would require more than one free slot, which may be the case
    when using GSO, XDP, or software hashing. (CVE-2021-28714) (CVE-2021-28714, CVE-2021-28715)

  - A flaw was found in the Linux SCTP stack. A blind attacker may be able to kill an existing SCTP
    association through invalid chunks if the attacker knows the IP-addresses and port numbers being used and
    the attacker can send packets with spoofed IP addresses. (CVE-2021-3772)

  - A memory leak flaw in the Linux kernel's hugetlbfs memory usage was found in the way the user maps some
    regions of memory twice using shmget() which are aligned to PUD alignment with the fault of some of the
    memory pages. A local user could use this flaw to get unauthorized access to some data. (CVE-2021-4002)

  - A data leak flaw was found in the way XFS_IOC_ALLOCSP IOCTL in the XFS filesystem allowed for size
    increase of files with unaligned size. A local attacker could use this flaw to leak data on the XFS
    filesystem otherwise not accessible to them. (CVE-2021-4155)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2023-1688.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/../../faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-20322.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28711.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28712.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28713.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28714.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28715.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3772.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4002.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4155.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3772");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-20322");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "kpatch.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");
include("hotfixes.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  var cve_list = make_list("CVE-2021-3772", "CVE-2021-4002", "CVE-2021-4155", "CVE-2021-20322", "CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28714", "CVE-2021-28715");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS-2023-1688");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}
var pkgs = [
    {'reference':'kernel-4.14.262-135.486.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.14.262-135.486.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-4.14.262-135.486.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-4.14.262-135.486.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-i686-4.14.262-135.486.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-x86_64-4.14.262-135.486.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.14.262-135.486.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.14.262-135.486.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.262-135.486.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.262-135.486.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.14.262-135.486.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.14.262-135.486.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-4.14.262-135.486.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-4.14.262-135.486.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-4.14.262-135.486.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-4.14.262-135.486.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.14.262-135.486.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.14.262-135.486.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-4.14.262-135.486.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-4.14.262-135.486.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-x86_64 / etc");
}