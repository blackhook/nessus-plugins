##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1585.
##

include('compat.inc');

if (description)
{
  script_id(144800);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id("CVE-2020-1472", "CVE-2020-14318", "CVE-2020-14323");
  script_xref(name:"ALAS", value:"2021-1585");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2020/09/21");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0008");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0121");
  script_xref(name:"CEA-ID", value:"CEA-2020-0101");
  script_xref(name:"CEA-ID", value:"CEA-2023-0016");

  script_name(english:"Amazon Linux 2 : ctdb (ALAS-2021-1585)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2021-1585 advisory.

  - A flaw was found in the way samba handled file and directory permissions. An authenticated user could use
    this flaw to gain access to certain file and directory information which otherwise would be unavailable to
    the attacker. (CVE-2020-14318)

  - A null pointer dereference flaw was found in samba's Winbind service in versions before 4.11.15, before
    4.12.9 and before 4.13.1. A local user could use this flaw to crash the winbind service causing denial of
    service. (CVE-2020-14323)

  - An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure
    channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon
    Elevation of Privilege Vulnerability'. (CVE-2020-1472)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1585.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14318");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14323");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1472");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update samba' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1472");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'ctdb-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'ctdb-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'ctdb-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'ctdb-tests-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'ctdb-tests-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'ctdb-tests-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libsmbclient-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libsmbclient-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libsmbclient-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libsmbclient-devel-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libsmbclient-devel-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libsmbclient-devel-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libwbclient-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libwbclient-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libwbclient-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libwbclient-devel-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libwbclient-devel-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libwbclient-devel-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-client-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-client-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-client-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-client-libs-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-client-libs-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-client-libs-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-common-4.10.16-9.amzn2.0.1', 'release':'AL2'},
    {'reference':'samba-common-libs-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-common-libs-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-common-libs-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-common-tools-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-common-tools-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-common-tools-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-dc-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-dc-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-dc-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-dc-libs-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-dc-libs-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-dc-libs-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-debuginfo-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-debuginfo-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-debuginfo-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-devel-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-devel-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-devel-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-krb5-printing-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-krb5-printing-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-krb5-printing-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-libs-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-libs-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-libs-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-pidl-4.10.16-9.amzn2.0.1', 'release':'AL2'},
    {'reference':'samba-python-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-python-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-python-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-python-test-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-python-test-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-python-test-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-test-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-test-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-test-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-test-libs-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-test-libs-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-test-libs-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-vfs-glusterfs-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-winbind-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-winbind-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-winbind-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-winbind-clients-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-winbind-clients-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-winbind-clients-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-winbind-krb5-locator-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-winbind-krb5-locator-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-winbind-krb5-locator-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'samba-winbind-modules-4.10.16-9.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'samba-winbind-modules-4.10.16-9.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'samba-winbind-modules-4.10.16-9.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-tests / libsmbclient / etc");
}