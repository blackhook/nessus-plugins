##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1583.
##

include('compat.inc');

if (description)
{
  script_id(144796);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/07");

  script_cve_id("CVE-2020-25654");
  script_xref(name:"ALAS", value:"2021-1583");

  script_name(english:"Amazon Linux 2 : pacemaker (ALAS-2021-1583)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the ALAS2-2021-1583 advisory.

  - An ACL bypass flaw was found in pacemaker. An attacker having a local account on the cluster and in the
    haclient group could use IPC communication with various daemons directly to perform certain tasks that
    they would be prevented by ACLs from doing if they went through the configuration. (CVE-2020-25654)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1583.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25654");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update pacemaker' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25654");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-cluster-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-cts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-nagios-plugins-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-remote");
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
    {'reference':'pacemaker-1.1.23-1.amzn2.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pacemaker-1.1.23-1.amzn2.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pacemaker-1.1.23-1.amzn2.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pacemaker-cli-1.1.23-1.amzn2.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pacemaker-cli-1.1.23-1.amzn2.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pacemaker-cli-1.1.23-1.amzn2.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pacemaker-cluster-libs-1.1.23-1.amzn2.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pacemaker-cluster-libs-1.1.23-1.amzn2.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pacemaker-cluster-libs-1.1.23-1.amzn2.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pacemaker-cts-1.1.23-1.amzn2.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pacemaker-cts-1.1.23-1.amzn2.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pacemaker-cts-1.1.23-1.amzn2.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pacemaker-debuginfo-1.1.23-1.amzn2.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pacemaker-debuginfo-1.1.23-1.amzn2.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pacemaker-debuginfo-1.1.23-1.amzn2.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pacemaker-doc-1.1.23-1.amzn2.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pacemaker-doc-1.1.23-1.amzn2.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pacemaker-doc-1.1.23-1.amzn2.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pacemaker-libs-1.1.23-1.amzn2.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pacemaker-libs-1.1.23-1.amzn2.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pacemaker-libs-1.1.23-1.amzn2.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pacemaker-libs-devel-1.1.23-1.amzn2.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pacemaker-libs-devel-1.1.23-1.amzn2.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pacemaker-libs-devel-1.1.23-1.amzn2.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pacemaker-nagios-plugins-metadata-1.1.23-1.amzn2.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pacemaker-nagios-plugins-metadata-1.1.23-1.amzn2.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pacemaker-nagios-plugins-metadata-1.1.23-1.amzn2.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pacemaker-remote-1.1.23-1.amzn2.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pacemaker-remote-1.1.23-1.amzn2.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pacemaker-remote-1.1.23-1.amzn2.1', 'cpu':'x86_64', 'release':'AL2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pacemaker / pacemaker-cli / pacemaker-cluster-libs / etc");
}