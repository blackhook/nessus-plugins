#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:095. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66107);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2012-3174",
    "CVE-2013-0169",
    "CVE-2013-0422",
    "CVE-2013-0424",
    "CVE-2013-0425",
    "CVE-2013-0426",
    "CVE-2013-0427",
    "CVE-2013-0428",
    "CVE-2013-0429",
    "CVE-2013-0431",
    "CVE-2013-0432",
    "CVE-2013-0433",
    "CVE-2013-0434",
    "CVE-2013-0435",
    "CVE-2013-0440",
    "CVE-2013-0441",
    "CVE-2013-0442",
    "CVE-2013-0443",
    "CVE-2013-0444",
    "CVE-2013-0445",
    "CVE-2013-0450",
    "CVE-2013-0809",
    "CVE-2013-1475",
    "CVE-2013-1476",
    "CVE-2013-1478",
    "CVE-2013-1480",
    "CVE-2013-1484",
    "CVE-2013-1485",
    "CVE-2013-1486",
    "CVE-2013-1493"
  );
  script_bugtraq_id(
    57246,
    57312,
    57686,
    57687,
    57689,
    57691,
    57692,
    57694,
    57696,
    57701,
    57702,
    57703,
    57709,
    57710,
    57711,
    57712,
    57713,
    57715,
    57719,
    57724,
    57726,
    57727,
    57729,
    57730,
    57778,
    58027,
    58028,
    58029,
    58238,
    58296
  );
  script_xref(name:"MDVSA", value:"2013:095");
  script_xref(name:"MGASA", value:"2013-0018");
  script_xref(name:"MGASA", value:"2013-0056");
  script_xref(name:"MGASA", value:"2013-0084");
  script_xref(name:"MGASA", value:"2013-0088");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"Mandriva Linux Security Advisory : java-1.7.0-openjdk (MDVSA-2013:095)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mandriva Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"Updated java-1.7.0-openjdk packages fix security vulnerabilities :

Two improper permission check issues were discovered in the reflection
API in OpenJDK. An untrusted Java application or applet could use
these flaws to bypass Java sandbox restrictions (CVE-2012-3174,
CVE-2013-0422).

Multiple improper permission check issues were discovered in the AWT,
CORBA, JMX, Libraries, and Beans components in OpenJDK. An untrusted
Java application or applet could use these flaws to bypass Java
sandbox restrictions (CVE-2013-0442, CVE-2013-0445, CVE-2013-0441,
CVE-2013-1475, CVE-2013-1476, CVE-2013-0429, CVE-2013-0450,
CVE-2013-0425, CVE-2013-0426, CVE-2013-0428, CVE-2013-0444).

Multiple flaws were found in the way image parsers in the 2D and AWT
components handled image raster parameters. A specially crafted image
could cause Java Virtual Machine memory corruption and, possibly, lead
to arbitrary code execution with the virtual machine privileges
(CVE-2013-1478, CVE-2013-1480).

A flaw was found in the AWT component's clipboard handling code. An
untrusted Java application or applet could use this flaw to access
clipboard data, bypassing Java sandbox restrictions (CVE-2013-0432).

The default Java security properties configuration did not restrict
access to certain com.sun.xml.internal packages. An untrusted Java
application or applet could use this flaw to access information,
bypassing certain Java sandbox restrictions. This update lists the
whole package as restricted (CVE-2013-0435).

Multiple improper permission check issues were discovered in the JMX,
Libraries, Networking, and JAXP components. An untrusted Java
application or applet could use these flaws to bypass certain Java
sandbox restrictions (CVE-2013-0431, CVE-2013-0427, CVE-2013-0433,
CVE-2013-0434).

It was discovered that the RMI component's CGIHandler class used user
inputs in error messages without any sanitization. An attacker could
use this flaw to perform a cross-site scripting (XSS) attack
(CVE-2013-0424).

It was discovered that the SSL/TLS implementation in the JSSE
component did not properly enforce handshake message ordering,
allowing an unlimited number of handshake restarts. A remote attacker
could use this flaw to make an SSL/TLS server using JSSE consume an
excessive amount of CPU by continuously restarting the handshake
(CVE-2013-0440).

It was discovered that the JSSE component did not properly validate
Diffie-Hellman public keys. An SSL/TLS client could possibly use this
flaw to perform a small subgroup attack (CVE-2013-0443).

Multiple improper permission check issues were discovered in the JMX
and Libraries components in OpenJDK. An untrusted Java application or
applet could use these flaws to bypass Java sandbox restrictions
(CVE-2013-1486, CVE-2013-1484).

An improper permission check issue was discovered in the Libraries
component in OpenJDK. An untrusted Java application or applet could
use this flaw to bypass certain Java sandbox restrictions
(CVE-2013-1485).

It was discovered that OpenJDK leaked timing information when
decrypting TLS/SSL protocol encrypted records when CBC-mode cipher
suites were used. A remote attacker could possibly use this flaw to
retrieve plain text from the encrypted packets by using a TLS/SSL
server as a padding oracle (CVE-2013-0169).

An integer overflow flaw was found in the way the 2D component handled
certain sample model instances. A specially crafted sample model
instance could cause Java Virtual Machine memory corruption and,
possibly, lead to arbitrary code execution with virtual machine
privileges (CVE-2013-0809).

It was discovered that the 2D component did not properly reject
certain malformed images. Specially crafted raster parameters could
cause Java Virtual Machine memory corruption and, possibly, lead to
arbitrary code execution with virtual machine privileges
(CVE-2013-1493).");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java CMM Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.6-2.3.8.1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.6-2.3.8.1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.6-2.3.8.1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"java-1.7.0-openjdk-javadoc-1.7.0.6-2.3.8.1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.6-2.3.8.1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
