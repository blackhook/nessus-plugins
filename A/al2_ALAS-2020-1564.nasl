##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1564.
##

include('compat.inc');

if (description)
{
  script_id(143579);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/09");

  script_cve_id("CVE-2020-8622", "CVE-2020-8623", "CVE-2020-8624");
  script_xref(name:"ALAS", value:"2020-1564");

  script_name(english:"Amazon Linux 2 : bind (ALAS-2020-1564)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2020-1564 advisory.

  - In BIND 9.0.0 -> 9.11.21, 9.12.0 -> 9.16.5, 9.17.0 -> 9.17.3, also affects 9.9.3-S1 -> 9.11.21-S1 of the
    BIND 9 Supported Preview Edition, An attacker on the network path for a TSIG-signed request, or operating
    the server receiving the TSIG-signed request, could send a truncated response to that request, triggering
    an assertion failure, causing the server to exit. Alternately, an off-path attacker would have to
    correctly guess when a TSIG-signed request was sent, along with other characteristics of the packet and
    message, and spoof a truncated response to trigger an assertion failure, causing the server to exit.
    (CVE-2020-8622)

  - In BIND 9.10.0 -> 9.11.21, 9.12.0 -> 9.16.5, 9.17.0 -> 9.17.3, also affects 9.10.5-S1 -> 9.11.21-S1 of the
    BIND 9 Supported Preview Edition, An attacker that can reach a vulnerable system with a specially crafted
    query packet can trigger a crash. To be vulnerable, the system must: * be running BIND that was built with
    --enable-native-pkcs11 * be signing one or more zones with an RSA key * be able to receive queries from
    a possible attacker (CVE-2020-8623)

  - In BIND 9.9.12 -> 9.9.13, 9.10.7 -> 9.10.8, 9.11.3 -> 9.11.21, 9.12.1 -> 9.16.5, 9.17.0 -> 9.17.3, also
    affects 9.9.12-S1 -> 9.9.13-S1, 9.11.3-S1 -> 9.11.21-S1 of the BIND 9 Supported Preview Edition, An
    attacker who has been granted privileges to change a specific subset of the zone's content could abuse
    these unintended additional privileges to update other contents of the zone. (CVE-2020-8624)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1564.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8622");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8623");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8624");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update bind' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'bind-9.11.4-26.P2.amzn2.2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'bind-9.11.4-26.P2.amzn2.2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'bind-9.11.4-26.P2.amzn2.2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'bind-chroot-9.11.4-26.P2.amzn2.2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'bind-chroot-9.11.4-26.P2.amzn2.2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'bind-chroot-9.11.4-26.P2.amzn2.2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'bind-debuginfo-9.11.4-26.P2.amzn2.2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'bind-debuginfo-9.11.4-26.P2.amzn2.2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'bind-debuginfo-9.11.4-26.P2.amzn2.2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'bind-devel-9.11.4-26.P2.amzn2.2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'bind-devel-9.11.4-26.P2.amzn2.2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'bind-devel-9.11.4-26.P2.amzn2.2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'bind-export-devel-9.11.4-26.P2.amzn2.2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'bind-export-devel-9.11.4-26.P2.amzn2.2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'bind-export-devel-9.11.4-26.P2.amzn2.2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'bind-export-libs-9.11.4-26.P2.amzn2.2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'bind-export-libs-9.11.4-26.P2.amzn2.2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'bind-export-libs-9.11.4-26.P2.amzn2.2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'bind-libs-9.11.4-26.P2.amzn2.2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'bind-libs-9.11.4-26.P2.amzn2.2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'bind-libs-9.11.4-26.P2.amzn2.2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'bind-libs-lite-9.11.4-26.P2.amzn2.2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'bind-libs-lite-9.11.4-26.P2.amzn2.2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'bind-libs-lite-9.11.4-26.P2.amzn2.2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'bind-license-9.11.4-26.P2.amzn2.2', 'release':'AL2'},
    {'reference':'bind-lite-devel-9.11.4-26.P2.amzn2.2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'bind-lite-devel-9.11.4-26.P2.amzn2.2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'bind-lite-devel-9.11.4-26.P2.amzn2.2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'bind-pkcs11-9.11.4-26.P2.amzn2.2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'bind-pkcs11-9.11.4-26.P2.amzn2.2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'bind-pkcs11-9.11.4-26.P2.amzn2.2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'bind-pkcs11-devel-9.11.4-26.P2.amzn2.2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'bind-pkcs11-devel-9.11.4-26.P2.amzn2.2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'bind-pkcs11-devel-9.11.4-26.P2.amzn2.2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'bind-pkcs11-libs-9.11.4-26.P2.amzn2.2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'bind-pkcs11-libs-9.11.4-26.P2.amzn2.2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'bind-pkcs11-libs-9.11.4-26.P2.amzn2.2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'bind-pkcs11-utils-9.11.4-26.P2.amzn2.2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'bind-pkcs11-utils-9.11.4-26.P2.amzn2.2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'bind-pkcs11-utils-9.11.4-26.P2.amzn2.2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'bind-sdb-9.11.4-26.P2.amzn2.2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'bind-sdb-9.11.4-26.P2.amzn2.2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'bind-sdb-9.11.4-26.P2.amzn2.2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'bind-sdb-chroot-9.11.4-26.P2.amzn2.2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'bind-sdb-chroot-9.11.4-26.P2.amzn2.2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'bind-sdb-chroot-9.11.4-26.P2.amzn2.2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'bind-utils-9.11.4-26.P2.amzn2.2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'bind-utils-9.11.4-26.P2.amzn2.2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'bind-utils-9.11.4-26.P2.amzn2.2', 'cpu':'x86_64', 'release':'AL2'}
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