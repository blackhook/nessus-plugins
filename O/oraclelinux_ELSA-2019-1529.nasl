#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:1529 and 
# Oracle Linux Security Advisory ELSA-2019-1529 respectively.
#

include("compat.inc");

if (description)
{
  script_id(127594);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/15");

  script_cve_id("CVE-2018-11784", "CVE-2018-8014", "CVE-2018-8034", "CVE-2018-8037");
  script_xref(name:"RHSA", value:"2019:1529");

  script_name(english:"Oracle Linux 8 : pki-deps:10.6 (ELSA-2019-1529)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"From Red Hat Security Advisory 2019:1529 :

An update for the pki-deps:10.6 module is now available for Red Hat
Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Public Key Infrastructure (PKI) Deps module contains fundamental
packages required as dependencies for the pki-core module by Red Hat
Certificate System.

Security Fix(es) :

* tomcat: Due to a mishandling of close in NIO/NIO2 connectors user
sessions can get mixed up (CVE-2018-8037)

* tomcat: Insecure defaults in CORS filter enable
'supportsCredentials' for all origins (CVE-2018-8014)

* tomcat: Open redirect in default servlet (CVE-2018-11784)

* tomcat: Host name verification missing in WebSocket client
(CVE-2018-8034)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-August/008981.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected pki-deps:10.6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apache-commons-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apache-commons-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bea-stax-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glassfish-fastinfoset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glassfish-jaxb-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glassfish-jaxb-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glassfish-jaxb-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glassfish-jaxb-txw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jackson-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jackson-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jackson-jaxrs-json-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jackson-jaxrs-providers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jackson-module-jaxb-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jakarta-commons-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:javassist-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-servlet-4.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-servlet-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-nss-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:relaxngDatatype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:slf4j-jdk14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:stax-ex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:velocity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xml-commons-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xml-commons-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xmlstreambuffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xsom");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 8", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"apache-commons-collections-3.2.2-10.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"apache-commons-lang-2.6-21.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bea-stax-api-1.2.0-16.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"glassfish-fastinfoset-1.2.13-9.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"glassfish-jaxb-api-2.2.12-8.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"glassfish-jaxb-core-2.2.11-11.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"glassfish-jaxb-runtime-2.2.11-11.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"glassfish-jaxb-txw2-2.2.11-11.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"jackson-annotations-2.9.8-1.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"jackson-core-2.9.8-1.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"jackson-databind-2.9.8-1.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"jackson-jaxrs-json-provider-2.9.8-1.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"jackson-jaxrs-providers-2.9.8-1.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"jackson-module-jaxb-annotations-2.7.6-4.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"jakarta-commons-httpclient-3.1-28.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"javassist-3.18.1-8.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"javassist-javadoc-3.18.1-8.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"pki-servlet-4.0-api-9.0.7-14.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"pki-servlet-container-9.0.7-14.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python-nss-doc-1.0.1-10.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python3-nss-1.0.1-10.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"relaxngDatatype-2011.1-7.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"resteasy-3.0.26-3.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"slf4j-1.7.25-4.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"slf4j-jdk14-1.7.25-4.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"stax-ex-1.7.7-8.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"velocity-1.7-24.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"xalan-j2-2.7.1-38.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"xerces-j2-2.11.0-34.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"xml-commons-apis-1.4.01-25.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"xml-commons-resolver-1.2-26.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"xmlstreambuffer-1.5.4-8.module+el8.0.0+5231+3e842911")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"xsom-0-19.20110809svn.module+el8.0.0+5231+3e842911")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache-commons-collections / apache-commons-lang / bea-stax-api / etc");
}
