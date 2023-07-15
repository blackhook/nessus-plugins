#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2022-1564.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158192);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id(
    "CVE-2016-2124",
    "CVE-2020-25717",
    "CVE-2021-20254",
    "CVE-2021-44142"
  );
  script_xref(name:"IAVA", value:"2021-A-0208-S");
  script_xref(name:"IAVA", value:"2022-A-0054-S");
  script_xref(name:"ALAS", value:"2022-1564");

  script_name(english:"Amazon Linux AMI : samba (ALAS-2022-1564)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of samba installed on the remote host is prior to 4.10.16-18.59. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS-2022-1564 advisory.

  - The Samba vfs_fruit module uses extended file attributes (EA, xattr) to provide ...enhanced compatibility
    with Apple SMB clients and interoperability with a Netatalk 3 AFP fileserver. Samba versions prior to
    4.13.17, 4.14.12 and 4.15.5 with vfs_fruit configured allow out-of-bounds heap read and write via
    specially crafted extended file attributes. A remote attacker with write access to extended file
    attributes can execute arbitrary code with the privileges of smbd, typically root. (CVE-2021-44142)

  - A flaw was found in the way samba implemented SMB1 authentication. An attacker could use this flaw to
    retrieve the plaintext password sent over the wire even if Kerberos authentication was required.
    (CVE-2016-2124)

  - A flaw was found in the way Samba maps domain users to local users. An authenticated attacker could use
    this flaw to cause possible privilege escalation. (CVE-2020-25717)

  - A flaw was found in samba. The Samba smbd file server must map Windows group identities (SIDs) into unix
    group ids (gids). The code that performs this had a flaw that could allow it to read data beyond the end
    of the array in the case where a negative cache entry had been added to the mapping cache. This could
    cause the calling code to return those values into the process token that stores the group membership for
    a user. The highest threat from this vulnerability is to data confidentiality and integrity.
    (CVE-2021-20254)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2022-1564.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2016-2124.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-25717.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-20254.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-44142.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update samba' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44142");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/19");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'ctdb-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ctdb-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ctdb-tests-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ctdb-tests-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-devel-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-devel-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-devel-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-devel-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-libs-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-libs-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-4.10.16-18.59.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-libs-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-libs-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-tools-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-tools-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-debuginfo-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-debuginfo-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-devel-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-devel-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-krb5-printing-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-krb5-printing-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-pidl-4.10.16-18.59.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-python-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-python-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-python-test-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-python-test-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-libs-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-libs-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-clients-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-clients-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-krb5-locator-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-krb5-locator-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-modules-4.10.16-18.59.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-modules-4.10.16-18.59.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var allowmaj = NULL;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-tests / libsmbclient / etc");
}