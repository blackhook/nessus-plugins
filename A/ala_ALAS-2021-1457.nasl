##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2021-1457.
##

include('compat.inc');

if (description)
{
  script_id(144994);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2020-8622");
  script_xref(name:"ALAS", value:"2021-1457");

  script_name(english:"Amazon Linux AMI : bind (ALAS-2021-1457)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of bind installed on the remote host is prior to 9.8.2-0.68.rc1.85. It is, therefore, affected by a
vulnerability as referenced in the ALAS-2021-1457 advisory.

  - In BIND 9.0.0 -> 9.11.21, 9.12.0 -> 9.16.5, 9.17.0 -> 9.17.3, also affects 9.9.3-S1 -> 9.11.21-S1 of the
    BIND 9 Supported Preview Edition, An attacker on the network path for a TSIG-signed request, or operating
    the server receiving the TSIG-signed request, could send a truncated response to that request, triggering
    an assertion failure, causing the server to exit. Alternately, an off-path attacker would have to
    correctly guess when a TSIG-signed request was sent, along with other characteristics of the packet and
    message, and spoof a truncated response to trigger an assertion failure, causing the server to exit.
    (CVE-2020-8622)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2021-1457.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8622");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update bind' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8622");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'bind-9.8.2-0.68.rc1.85.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'bind-9.8.2-0.68.rc1.85.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'bind-chroot-9.8.2-0.68.rc1.85.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'bind-chroot-9.8.2-0.68.rc1.85.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'bind-debuginfo-9.8.2-0.68.rc1.85.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'bind-debuginfo-9.8.2-0.68.rc1.85.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'bind-devel-9.8.2-0.68.rc1.85.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'bind-devel-9.8.2-0.68.rc1.85.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'bind-libs-9.8.2-0.68.rc1.85.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'bind-libs-9.8.2-0.68.rc1.85.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'bind-sdb-9.8.2-0.68.rc1.85.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'bind-sdb-9.8.2-0.68.rc1.85.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'bind-utils-9.8.2-0.68.rc1.85.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'bind-utils-9.8.2-0.68.rc1.85.amzn1', 'cpu':'x86_64', 'release':'ALA'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-debuginfo / etc");
}