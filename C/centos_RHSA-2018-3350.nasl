#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3350 and 
# CentOS Errata and Security Advisory 2018:3350 respectively.
#

include('compat.inc');

if (description)
{
  script_id(119045);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/26");

  script_cve_id(
    "CVE-2018-3136",
    "CVE-2018-3139",
    "CVE-2018-3149",
    "CVE-2018-3169",
    "CVE-2018-3180",
    "CVE-2018-3214"
  );
  script_xref(name:"RHSA", value:"2018:3350");

  script_name(english:"CentOS 7 : java-1.7.0-openjdk (CESA-2018:3350)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for java-1.7.0-openjdk is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.7.0-openjdk packages provide the OpenJDK 7 Java Runtime
Environment and the OpenJDK 7 Java Software Development Kit.

Security Fix(es) :

* OpenJDK: Improper field access checks (Hotspot, 8199226)
(CVE-2018-3169)

* OpenJDK: Incomplete enforcement of the trustURLCodebase restriction
(JNDI, 8199177) (CVE-2018-3149)

* OpenJDK: Incorrect handling of unsigned attributes in signed Jar
manifests (Security, 8194534) (CVE-2018-3136)

* OpenJDK: Leak of sensitive header data via HTTP redirect
(Networking, 8196902) (CVE-2018-3139)

* OpenJDK: Missing endpoint identification algorithm check during TLS
session resumption (JSSE, 8202613) (CVE-2018-3180)

* OpenJDK: Infinite loop in RIFF format reader (Sound, 8205361)
(CVE-2018-3214)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.");
  # https://lists.centos.org/pipermail/centos-announce/2018-December/023106.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10ebcf8f");
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005751.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0422129f");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.7.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3180");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-3169");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.201-2.6.16.1.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-accessibility-1.7.0.201-2.6.16.1.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.201-2.6.16.1.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.201-2.6.16.1.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-headless-1.7.0.201-2.6.16.1.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-javadoc-1.7.0.201-2.6.16.1.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.201-2.6.16.1.el7_6")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-accessibility / etc");
}
