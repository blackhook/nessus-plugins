#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1683.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151275);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/01");

  script_cve_id(
    "CVE-2019-25032",
    "CVE-2019-25034",
    "CVE-2019-25035",
    "CVE-2019-25036",
    "CVE-2019-25037",
    "CVE-2019-25038",
    "CVE-2019-25039",
    "CVE-2019-25040",
    "CVE-2019-25041",
    "CVE-2019-25042",
    "CVE-2020-28935"
  );
  script_xref(name:"ALAS", value:"2021-1683");

  script_name(english:"Amazon Linux 2 : unbound (ALAS-2021-1683)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of unbound installed on the remote host is prior to 1.7.3-15. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2021-1683 advisory.

  - ** DISPUTED ** Unbound before 1.9.5 allows an integer overflow in the regional allocator via
    regional_alloc. NOTE: The vendor disputes that this is a vulnerability. Although the code may be
    vulnerable, a running Unbound installation cannot be remotely or locally exploited. (CVE-2019-25032)

  - ** DISPUTED ** Unbound before 1.9.5 allows an integer overflow in sldns_str2wire_dname_buf_origin, leading
    to an out-of-bounds write. NOTE: The vendor disputes that this is a vulnerability. Although the code may
    be vulnerable, a running Unbound installation cannot be remotely or locally exploited. (CVE-2019-25034)

  - ** DISPUTED ** Unbound before 1.9.5 allows an out-of-bounds write in sldns_bget_token_par. NOTE: The
    vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running Unbound
    installation cannot be remotely or locally exploited. (CVE-2019-25035)

  - ** DISPUTED ** Unbound before 1.9.5 allows an assertion failure and denial of service in synth_cname.
    NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running
    Unbound installation cannot be remotely or locally exploited. (CVE-2019-25036)

  - ** DISPUTED ** Unbound before 1.9.5 allows an assertion failure and denial of service in dname_pkt_copy
    via an invalid packet. NOTE: The vendor disputes that this is a vulnerability. Although the code may be
    vulnerable, a running Unbound installation cannot be remotely or locally exploited. (CVE-2019-25037)

  - ** DISPUTED ** Unbound before 1.9.5 allows an integer overflow in a size calculation in
    dnscrypt/dnscrypt.c. NOTE: The vendor disputes that this is a vulnerability. Although the code may be
    vulnerable, a running Unbound installation cannot be remotely or locally exploited. (CVE-2019-25038)

  - ** DISPUTED ** Unbound before 1.9.5 allows an integer overflow in a size calculation in respip/respip.c.
    NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running
    Unbound installation cannot be remotely or locally exploited. (CVE-2019-25039)

  - ** DISPUTED ** Unbound before 1.9.5 allows an infinite loop via a compressed name in dname_pkt_copy. NOTE:
    The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running Unbound
    installation cannot be remotely or locally exploited. (CVE-2019-25040)

  - ** DISPUTED ** Unbound before 1.9.5 allows an assertion failure via a compressed name in dname_pkt_copy.
    NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running
    Unbound installation cannot be remotely or locally exploited. (CVE-2019-25041)

  - ** DISPUTED ** Unbound before 1.9.5 allows an out-of-bounds write via a compressed name in rdata_copy.
    NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running
    Unbound installation cannot be remotely or locally exploited. (CVE-2019-25042)

  - NLnet Labs Unbound, up to and including version 1.12.0, and NLnet Labs NSD, up to and including version
    4.3.3, contain a local vulnerability that would allow for a local symlink attack. When writing the PID
    file, Unbound and NSD create the file if it is not there, or open an existing file for writing. In case
    the file was already present, they would follow symlinks if the file happened to be a symlink instead of a
    regular file. An additional chown of the file would then take place after it was written, making the user
    Unbound/NSD is supposed to run as the new owner of the file. If an attacker has local access to the user
    Unbound/NSD runs as, she could create a symlink in place of the PID file pointing to a file that she would
    like to erase. If then Unbound/NSD is killed and the PID file is not cleared, upon restarting with root
    privileges, Unbound/NSD will rewrite any file pointed at by the symlink. This is a local vulnerability
    that could create a Denial of Service of the system Unbound/NSD is running on. It requires an attacker
    having access to the limited permission user Unbound/NSD runs as and point through the symlink to a
    critical file on the system. (CVE-2020-28935)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1683.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-25032");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-25034");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-25035");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-25036");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-25037");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-25038");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-25039");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-25040");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-25041");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-25042");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-28935");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update unbound' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-25042");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python2-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:unbound-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:unbound-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:unbound-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'python2-unbound-1.7.3-15.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-unbound-1.7.3-15.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-unbound-1.7.3-15.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-unbound-1.7.3-15.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-unbound-1.7.3-15.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-unbound-1.7.3-15.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-1.7.3-15.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-1.7.3-15.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-1.7.3-15.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-debuginfo-1.7.3-15.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-debuginfo-1.7.3-15.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-debuginfo-1.7.3-15.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-devel-1.7.3-15.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-devel-1.7.3-15.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-devel-1.7.3-15.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-libs-1.7.3-15.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-libs-1.7.3-15.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-libs-1.7.3-15.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2-unbound / python3-unbound / unbound / etc");
}