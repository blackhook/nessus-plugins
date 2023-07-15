#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2985 and 
# Oracle Linux Security Advisory ELSA-2020-2985 respectively.
#

include('compat.inc');

if (description)
{
  script_id(138667);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2020-14556",
    "CVE-2020-14577",
    "CVE-2020-14578",
    "CVE-2020-14579",
    "CVE-2020-14583",
    "CVE-2020-14593",
    "CVE-2020-14621"
  );
  script_xref(name:"RHSA", value:"2020:2985");
  script_xref(name:"IAVA", value:"2020-A-0322-S");

  script_name(english:"Oracle Linux 6 : java-1.8.0-openjdk (ELSA-2020-2985)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"From Red Hat Security Advisory 2020:2985 :

The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:2985 advisory.

  - OpenJDK: Incorrect handling of access control context in
    ForkJoinPool (Libraries, 8237117) (CVE-2020-14556)

  - OpenJDK: HostnameChecker does not ensure X.509
    certificate names are in normalized form (JSSE, 8237592)
    (CVE-2020-14577)

  - OpenJDK: Unexpected exception raised by DerInputStream
    (Libraries, 8237731) (CVE-2020-14578)

  - OpenJDK: Unexpected exception raised by
    DerValue.equals() (Libraries, 8237736) (CVE-2020-14579)

  - OpenJDK: Bypass of boundary checks in nio.Buffer via
    concurrent access (Libraries, 8238920) (CVE-2020-14583)

  - OpenJDK: Incomplete bounds checks in Affine
    Transformations (2D, 8240119) (CVE-2020-14593)

  - OpenJDK: XML validation manipulation due to incomplete
    application of the use-grammar-pool-only feature (JAXP,
    8242136) (CVE-2020-14621)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2020-July/010133.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.8.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14556");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14583");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-1.8.0.262.b10-0.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-debug-1.8.0.262.b10-0.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-demo-1.8.0.262.b10-0.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.262.b10-0.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-devel-1.8.0.262.b10-0.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.262.b10-0.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-headless-1.8.0.262.b10-0.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.262.b10-0.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-javadoc-1.8.0.262.b10-0.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.262.b10-0.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-src-1.8.0.262.b10-0.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-src-debug-1.8.0.262.b10-0.el6_10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-debug / etc");
}
