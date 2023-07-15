#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:3127 and 
# Oracle Linux Security Advisory ELSA-2019-3127 respectively.
#

include('compat.inc');

if (description)
{
  script_id(129988);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-2945",
    "CVE-2019-2949",
    "CVE-2019-2962",
    "CVE-2019-2964",
    "CVE-2019-2973",
    "CVE-2019-2975",
    "CVE-2019-2977",
    "CVE-2019-2978",
    "CVE-2019-2981",
    "CVE-2019-2983",
    "CVE-2019-2987",
    "CVE-2019-2988",
    "CVE-2019-2989",
    "CVE-2019-2992",
    "CVE-2019-2999"
  );
  script_xref(name:"RHSA", value:"2019:3127");

  script_name(english:"Oracle Linux 7 : java-11-openjdk (ELSA-2019-3127)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"From Red Hat Security Advisory 2019:3127 :

An update for java-11-openjdk is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-11-openjdk packages provide the OpenJDK 11 Java Runtime
Environment and the OpenJDK 11 Java Software Development Kit.

Security Fix(es) :

* OpenJDK: Improper handling of Kerberos proxy credentials (Kerberos,
8220302) (CVE-2019-2949)

* OpenJDK: Unexpected exception thrown during regular expression
processing in Nashorn (Scripting, 8223518) (CVE-2019-2975)

* OpenJDK: Out of bounds access in optimized String indexof
implementation (Hotspot, 8224062) (CVE-2019-2977)

* OpenJDK: Incorrect handling of nested jar: URLs in Jar URL handler
(Networking, 8223892) (CVE-2019-2978)

* OpenJDK: Incorrect handling of HTTP proxy responses in
HttpURLConnection (Networking, 8225298) (CVE-2019-2989)

* OpenJDK: Missing restrictions on use of custom SocketImpl
(Networking, 8218573) (CVE-2019-2945)

* OpenJDK: NULL pointer dereference in DrawGlyphList (2D, 8222690)
(CVE-2019-2962)

* OpenJDK: Unexpected exception thrown by Pattern processing crafted
regular expression (Concurrency, 8222684) (CVE-2019-2964)

* OpenJDK: Unexpected exception thrown by XPathParser processing
crafted XPath expression (JAXP, 8223505) (CVE-2019-2973)

* OpenJDK: Unexpected exception thrown by XPath processing crafted
XPath expression (JAXP, 8224532) (CVE-2019-2981)

* OpenJDK: Unexpected exception thrown during Font object
deserialization (Serialization, 8224915) (CVE-2019-2983)

* OpenJDK: Missing glyph bitmap image dimension check in
FreetypeFontScaler (2D, 8225286) (CVE-2019-2987)

* OpenJDK: Integer overflow in bounds check in SunGraphics2D (2D,
8225292) (CVE-2019-2988)

* OpenJDK: Excessive memory allocation in CMap when reading TrueType
font (2D, 8225597) (CVE-2019-2992)

* OpenJDK: Insufficient filtering of HTML event attributes in Javadoc
(Javadoc, 8226765) (CVE-2019-2999)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2019-October/009247.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-11-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2977");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2989");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-javadoc-zip-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-jmods-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-11.0.5.10-0.0.1.el7_7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-debug-11.0.5.10-0.0.1.el7_7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-demo-11.0.5.10-0.0.1.el7_7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-demo-debug-11.0.5.10-0.0.1.el7_7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-devel-11.0.5.10-0.0.1.el7_7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-devel-debug-11.0.5.10-0.0.1.el7_7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-headless-11.0.5.10-0.0.1.el7_7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-headless-debug-11.0.5.10-0.0.1.el7_7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-11.0.5.10-0.0.1.el7_7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-debug-11.0.5.10-0.0.1.el7_7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-zip-11.0.5.10-0.0.1.el7_7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-zip-debug-11.0.5.10-0.0.1.el7_7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-jmods-11.0.5.10-0.0.1.el7_7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-jmods-debug-11.0.5.10-0.0.1.el7_7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-src-11.0.5.10-0.0.1.el7_7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-src-debug-11.0.5.10-0.0.1.el7_7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-11-openjdk / java-11-openjdk-debug / java-11-openjdk-demo / etc");
}
