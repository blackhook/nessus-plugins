##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1515.
##

include('compat.inc');

if (description)
{
  script_id(141965);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/29");

  script_cve_id("CVE-2019-10143", "CVE-2019-13456", "CVE-2019-17185");
  script_xref(name:"ALAS", value:"2020-1515");

  script_name(english:"Amazon Linux 2 : freeradius (ALAS-2020-1515)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2020-1515 advisory.

  - ** DISPUTED ** It was discovered freeradius up to and including version 3.0.19 does not correctly
    configure logrotate, allowing a local attacker who already has control of the radiusd user to escalate his
    privileges to root, by tricking logrotate into writing a radiusd-writable file to a directory normally
    inaccessible by the radiusd user. NOTE: the upstream software maintainer has stated there is simply no
    way for anyone to gain privileges through this alleged issue. (CVE-2019-10143)

  - In FreeRADIUS 3.0 through 3.0.19, on average 1 in every 2048 EAP-pwd handshakes fails because the password
    element cannot be found within 10 iterations of the hunting and pecking loop. This leaks information that
    an attacker can use to recover the password of any user. This information leakage is similar to the
    Dragonblood attack and CVE-2019-9494. (CVE-2019-13456)

  - In FreeRADIUS 3.0.x before 3.0.20, the EAP-pwd module used a global OpenSSL BN_CTX instance to handle all
    handshakes. This mean multiple threads use the same BN_CTX instance concurrently, resulting in crashes
    when concurrent EAP-pwd handshakes are initiated. This can be abused by an adversary as a Denial-of-
    Service (DoS) attack. (CVE-2019-17185)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1515.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10143");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13456");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-17185");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update freeradius' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10143");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-utils");
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
    {'reference':'freeradius-3.0.13-15.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'freeradius-3.0.13-15.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'freeradius-3.0.13-15.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'freeradius-debuginfo-3.0.13-15.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'freeradius-debuginfo-3.0.13-15.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'freeradius-debuginfo-3.0.13-15.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'freeradius-devel-3.0.13-15.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'freeradius-devel-3.0.13-15.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'freeradius-devel-3.0.13-15.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'freeradius-doc-3.0.13-15.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'freeradius-doc-3.0.13-15.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'freeradius-doc-3.0.13-15.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'freeradius-krb5-3.0.13-15.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'freeradius-krb5-3.0.13-15.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'freeradius-krb5-3.0.13-15.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'freeradius-ldap-3.0.13-15.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'freeradius-ldap-3.0.13-15.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'freeradius-ldap-3.0.13-15.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'freeradius-mysql-3.0.13-15.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'freeradius-mysql-3.0.13-15.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'freeradius-mysql-3.0.13-15.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'freeradius-perl-3.0.13-15.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'freeradius-perl-3.0.13-15.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'freeradius-perl-3.0.13-15.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'freeradius-postgresql-3.0.13-15.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'freeradius-postgresql-3.0.13-15.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'freeradius-postgresql-3.0.13-15.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'freeradius-python-3.0.13-15.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'freeradius-python-3.0.13-15.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'freeradius-python-3.0.13-15.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'freeradius-sqlite-3.0.13-15.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'freeradius-sqlite-3.0.13-15.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'freeradius-sqlite-3.0.13-15.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'freeradius-unixODBC-3.0.13-15.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'freeradius-unixODBC-3.0.13-15.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'freeradius-unixODBC-3.0.13-15.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'freeradius-utils-3.0.13-15.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'freeradius-utils-3.0.13-15.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'freeradius-utils-3.0.13-15.amzn2', 'cpu':'x86_64', 'release':'AL2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius / freeradius-debuginfo / freeradius-devel / etc");
}