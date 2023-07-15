##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1630.
##

include('compat.inc');

if (description)
{
  script_id(148922);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/22");

  script_cve_id(
    "CVE-2019-10146",
    "CVE-2019-10179",
    "CVE-2019-10221",
    "CVE-2020-1721",
    "CVE-2020-25715",
    "CVE-2021-20179"
  );
  script_xref(name:"ALAS", value:"2021-1630");

  script_name(english:"Amazon Linux 2 : pki-core (ALAS-2021-1630)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2-2021-1630 advisory.

  - A Reflected Cross Site Scripting flaw was found in all pki-core 10.x.x versions module from the pki-core
    server due to the CA Agent Service not properly sanitizing the certificate request page. An attacker could
    inject a specially crafted value that will be executed on the victim's browser. (CVE-2019-10146)

  - A vulnerability was found in all pki-core 10.x.x versions, where the Key Recovery Authority (KRA) Agent
    Service did not properly sanitize recovery request search page, enabling a Reflected Cross Site Scripting
    (XSS) vulnerability. An attacker could trick an authenticated victim into executing specially crafted
    Javascript code. (CVE-2019-10179)

  - A Reflected Cross Site Scripting vulnerability was found in all pki-core 10.x.x versions, where the pki-ca
    module from the pki-core server. This flaw is caused by missing sanitization of the GET URL parameters. An
    attacker could abuse this flaw to trick an authenticated user into clicking a specially crafted link which
    can execute arbitrary code when viewed in a browser. (CVE-2019-10221)

  - A flaw was found in pki-core. An attacker who has successfully compromised a key could use this flaw to
    renew the corresponding certificate over and over again, as long as it is not explicitly revoked. The
    highest threat from this vulnerability is to data confidentiality and integrity. (CVE-2021-20179)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1630.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10146");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10179");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10221");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1721");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25715");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-20179");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update pki-core' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20179");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pki-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pki-base-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pki-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pki-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pki-kra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pki-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pki-symkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pki-tools");
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
    {'reference':'pki-base-10.5.18-12.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-base-java-10.5.18-12.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-ca-10.5.18-12.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-core-debuginfo-10.5.18-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-core-debuginfo-10.5.18-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-core-debuginfo-10.5.18-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-javadoc-10.5.18-12.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-kra-10.5.18-12.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-server-10.5.18-12.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-symkey-10.5.18-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-symkey-10.5.18-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-symkey-10.5.18-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-tools-10.5.18-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-tools-10.5.18-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-tools-10.5.18-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pki-base / pki-base-java / pki-ca / etc");
}