#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1433.
#

include('compat.inc');

if (description)
{
  script_id(140612);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/16");

  script_cve_id("CVE-2020-3327", "CVE-2020-3350", "CVE-2020-3481");
  script_xref(name:"ALAS", value:"2020-1433");

  script_name(english:"Amazon Linux AMI : clamav (ALAS-2020-1433)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS-2020-1433 advisory.

  - A vulnerability in the ARJ archive parsing module in Clam AntiVirus (ClamAV) Software versions 0.102.2
    could allow an unauthenticated, remote attacker to cause a denial of service condition on an affected
    device. The vulnerability is due to a heap buffer overflow read. An attacker could exploit this
    vulnerability by sending a crafted ARJ file to an affected device. An exploit could allow the attacker to
    cause the ClamAV scanning process crash, resulting in a denial of service condition. (CVE-2020-3327)

  - A vulnerability in the endpoint software of Cisco AMP for Endpoints and Clam AntiVirus could allow an
    authenticated, local attacker to cause the running software to delete arbitrary files on the system. The
    vulnerability is due to a race condition that could occur when scanning malicious files. An attacker with
    local shell access could exploit this vulnerability by executing a script that could trigger the race
    condition. A successful exploit could allow the attacker to delete arbitrary files on the system that the
    attacker would not normally have privileges to delete, producing system instability or causing the
    endpoint software to stop working. (CVE-2020-3350)

  - A vulnerability in the EGG archive parsing module in Clam AntiVirus (ClamAV) Software versions 0.102.0 -
    0.102.3 could allow an unauthenticated, remote attacker to cause a denial of service condition on an
    affected device. The vulnerability is due to a null pointer dereference. An attacker could exploit this
    vulnerability by sending a crafted EGG file to an affected device. An exploit could allow the attacker to
    cause the ClamAV scanning process crash, resulting in a denial of service condition. (CVE-2020-3481)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1433.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3327");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3350");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3481");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update clamav' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3350");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-update");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'clamav-0.102.4-1.44.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'clamav-0.102.4-1.44.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'clamav-data-0.102.4-1.44.amzn1', 'release':'ALA'},
    {'reference':'clamav-db-0.102.4-1.44.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'clamav-db-0.102.4-1.44.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'clamav-debuginfo-0.102.4-1.44.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'clamav-debuginfo-0.102.4-1.44.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'clamav-devel-0.102.4-1.44.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'clamav-devel-0.102.4-1.44.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'clamav-filesystem-0.102.4-1.44.amzn1', 'release':'ALA'},
    {'reference':'clamav-lib-0.102.4-1.44.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'clamav-lib-0.102.4-1.44.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'clamav-milter-0.102.4-1.44.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'clamav-milter-0.102.4-1.44.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'clamav-update-0.102.4-1.44.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'clamav-update-0.102.4-1.44.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'clamd-0.102.4-1.44.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'clamd-0.102.4-1.44.amzn1', 'cpu':'x86_64', 'release':'ALA'}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav / clamav-data / clamav-db / etc");
}
