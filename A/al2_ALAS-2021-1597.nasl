##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1597.
##

include('compat.inc');

if (description)
{
  script_id(146624);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2021-21261");
  script_xref(name:"ALAS", value:"2021-1597");

  script_name(english:"Amazon Linux 2 : flatpak (ALAS-2021-1597)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of flatpak installed on the remote host is prior to 1.0.9-10. It is, therefore, affected by a vulnerability
as referenced in the ALAS2-2021-1597 advisory.

  - Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux. A bug
    was discovered in the `flatpak-portal` service that can allow sandboxed applications to execute arbitrary
    code on the host system (a sandbox escape). This sandbox-escape bug is present in versions from 0.11.4 and
    before fixed versions 1.8.5 and 1.10.0. The Flatpak portal D-Bus service (`flatpak-portal`, also known by
    its D-Bus service name `org.freedesktop.portal.Flatpak`) allows apps in a Flatpak sandbox to launch their
    own subprocesses in a new sandbox instance, either with the same security settings as the caller or with
    more restrictive security settings. For example, this is used in Flatpak-packaged web browsers such as
    Chromium to launch subprocesses that will process untrusted web content, and give those subprocesses a
    more restrictive sandbox than the browser itself. In vulnerable versions, the Flatpak portal service
    passes caller-specified environment variables to non-sandboxed processes on the host system, and in
    particular to the `flatpak run` command that is used to launch the new sandbox instance. A malicious or
    compromised Flatpak app could set environment variables that are trusted by the `flatpak run` command, and
    use them to execute arbitrary code that is not in a sandbox. As a workaround, this vulnerability can be
    mitigated by preventing the `flatpak-portal` service from starting, but that mitigation will prevent many
    Flatpak apps from working correctly. This is fixed in versions 1.8.5 and 1.10.0. (CVE-2021-21261)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1597.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21261");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update flatpak' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21261");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flatpak-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flatpak-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flatpak-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flatpak-libs");
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
    {'reference':'flatpak-1.0.9-10.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'flatpak-1.0.9-10.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'flatpak-1.0.9-10.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'flatpak-builder-1.0.0-10.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'flatpak-builder-1.0.0-10.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'flatpak-builder-1.0.0-10.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'flatpak-debuginfo-1.0.9-10.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'flatpak-debuginfo-1.0.9-10.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'flatpak-debuginfo-1.0.9-10.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'flatpak-devel-1.0.9-10.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'flatpak-devel-1.0.9-10.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'flatpak-devel-1.0.9-10.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'flatpak-libs-1.0.9-10.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'flatpak-libs-1.0.9-10.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'flatpak-libs-1.0.9-10.amzn2', 'cpu':'x86_64', 'release':'AL2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flatpak / flatpak-builder / flatpak-debuginfo / etc");
}