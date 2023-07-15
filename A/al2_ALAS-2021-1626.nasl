##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1626.
##

include('compat.inc');

if (description)
{
  script_id(148921);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-11023");
  script_xref(name:"ALAS", value:"2021-1626");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Amazon Linux 2 : ipa (ALAS-2021-1626)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by a vulnerability as referenced in the ALAS2-2021-1626 advisory.

  - In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing 
    elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods
    (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.
    (CVE-2020-11023)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1626.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11023");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update ipa' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python2-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python2-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python2-ipaserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'ipa-client-4.6.8-5.amzn2.4.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-4.6.8-5.amzn2.4.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-4.6.8-5.amzn2.4.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-common-4.6.8-5.amzn2.4.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-common-4.6.8-5.amzn2.4.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-debuginfo-4.6.8-5.amzn2.4.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-debuginfo-4.6.8-5.amzn2.4.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-debuginfo-4.6.8-5.amzn2.4.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-python-compat-4.6.8-5.amzn2.4.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-4.6.8-5.amzn2.4.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-4.6.8-5.amzn2.4.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-4.6.8-5.amzn2.4.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-common-4.6.8-5.amzn2.4.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-dns-4.6.8-5.amzn2.4.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-4.6.8-5.amzn2.4.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-4.6.8-5.amzn2.4.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-4.6.8-5.amzn2.4.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipaclient-4.6.8-5.amzn2.4.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipalib-4.6.8-5.amzn2.4.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipaserver-4.6.8-5.amzn2.4.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-client / ipa-client-common / ipa-common / etc");
}