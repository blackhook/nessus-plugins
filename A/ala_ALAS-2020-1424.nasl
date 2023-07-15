#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1424.
#

include('compat.inc');

if (description)
{
  script_id(140088);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/31");

  script_cve_id("CVE-2019-10197", "CVE-2019-10218");
  script_xref(name:"ALAS", value:"2020-1424");

  script_name(english:"Amazon Linux AMI : ctdb (ALAS-2020-1424)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS-2020-1424 advisory.

  - A flaw was found in samba versions 4.9.x up to 4.9.13, samba 4.10.x up to 4.10.8 and samba 4.11.x up to
    4.11.0rc3, when certain parameters were set in the samba configuration file. An unauthenticated attacker
    could use this flaw to escape the shared directory and access the contents of directories outside the
    share. (CVE-2019-10197)

  - A flaw was found in the samba client, all samba versions before samba 4.11.2, 4.10.10 and 4.9.15, where a
    malicious server can supply a pathname to the client with separators. This could allow the client to
    access files and folders outside of the SMB network pathnames. An attacker could use this vulnerability to
    create files outside of the current working directory using the privileges of the client user.
    (CVE-2019-10218)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1424.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10197");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10218");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update samba' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10197");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/31");

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
    {'reference':'ctdb-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'ctdb-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'ctdb-tests-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'ctdb-tests-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'libsmbclient-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'libsmbclient-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'libsmbclient-devel-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'libsmbclient-devel-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'libwbclient-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'libwbclient-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'libwbclient-devel-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'libwbclient-devel-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-client-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-client-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-client-libs-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-client-libs-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-common-4.10.4-11.51.amzn1', 'release':'ALA'},
    {'reference':'samba-common-libs-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-common-libs-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-common-tools-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-common-tools-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-debuginfo-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-debuginfo-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-devel-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-devel-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-krb5-printing-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-krb5-printing-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-libs-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-libs-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-pidl-4.10.4-11.51.amzn1', 'release':'ALA'},
    {'reference':'samba-python-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-python-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-python-test-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-python-test-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-test-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-test-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-test-libs-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-test-libs-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-winbind-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-winbind-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-winbind-clients-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-winbind-clients-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-winbind-krb5-locator-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-winbind-krb5-locator-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'samba-winbind-modules-4.10.4-11.51.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'samba-winbind-modules-4.10.4-11.51.amzn1', 'cpu':'x86_64', 'release':'ALA'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-tests / libsmbclient / etc");
}
