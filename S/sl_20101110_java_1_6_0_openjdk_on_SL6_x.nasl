#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(60892);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-3555", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3551", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3557", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3564", "CVE-2010-3565", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3573", "CVE-2010-3574");

  script_name(english:"Scientific Linux Security Update : java-1.6.0-openjdk on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"defaultReadObject of the Serialization API could be tricked into
setting a volatile field multiple times, which could allow a remote
attacker to execute arbitrary code with the privileges of the user
running the applet or application. (CVE-2010-3569)

Race condition in the way objects were deserialized could allow an
untrusted applet or application to misuse the privileges of the user
running the applet or application. (CVE-2010-3568)

Miscalculation in the OpenType font rendering implementation caused
out-of-bounds memory access, which could allow remote attackers to
execute code with the privileges of the user running the java process.
(CVE-2010-3567)

JPEGImageWriter.writeImage in the imageio API improperly checked
certain image metadata, which could allow a remote attacker to execute
arbitrary code in the context of the user running the applet or
application. (CVE-2010-3565)

Double free in IndexColorModel could cause an untrusted applet or
application to crash or, possibly, execute arbitrary code with the
privileges of the user running the applet or application.
(CVE-2010-3562)

The privileged accept method of the ServerSocket class in the Common
Object Request Broker Architecture (CORBA) implementation in OpenJDK
allowed it to receive connections from any host, instead of just the
host of the current connection. An attacker could use this flaw to
bypass restrictions defined by network permissions. (CVE-2010-3561)

Flaws in the Swing library could allow an untrusted application to
modify the behavior and state of certain JDK classes. (CVE-2010-3557)

Flaws in the CORBA implementation could allow an attacker to execute
arbitrary code by misusing permissions granted to certain system
objects. (CVE-2010-3554)

UIDefault.ProxyLazyValue had unsafe reflection usage, allowing
untrusted callers to create objects via ProxyLazyValue values.
(CVE-2010-3553)

HttpURLConnection improperly handled the 'chunked' transfer encoding
method, which could allow remote attackers to conduct HTTP response
splitting attacks. (CVE-2010-3549)

HttpURLConnection improperly checked whether the calling code was
granted the 'allowHttpTrace' permission, allowing untrusted code to
create HTTP TRACE requests. (CVE-2010-3574)

HttpURLConnection did not validate request headers set by applets,
which could allow remote attackers to trigger actions otherwise
restricted to HTTP clients. (CVE-2010-3541, CVE-2010-3573)

The Kerberos implementation improperly checked the sanity of AP-REQ
requests, which could cause a denial of service condition in the
receiving Java Virtual Machine. (CVE-2010-3564)

The java-1.6.0-openjdk packages shipped with the GA release of Red Hat
Enterprise Linux 6 mitigated a man-in-the-middle attack in the way the
TLS/SSL protocols handle session renegotiation by disabling
renegotiation. This update implements the TLS Renegotiation Indication
Extension as defined in RFC 5746, allowing secure renegotiation
between updated clients and servers. (CVE-2009-3555)

The NetworkInterface class improperly checked the network 'connect'
permissions for local network addresses, which could allow remote
attackers to read local network addresses. (CVE-2010-3551)

Information leak flaw in the Java Naming and Directory Interface
(JNDI) could allow a remote attacker to access information about
otherwise-protected internal network names. (CVE-2010-3548)

Note: Flaws concerning applets in this advisory (CVE-2010-3568,
CVE-2010-3554, CVE-2009-3555, CVE-2010-3562, CVE-2010-3557,
CVE-2010-3548, CVE-2010-3564, CVE-2010-3565, CVE-2010-3569) can only
be triggered in OpenJDK by calling the 'appletviewer' application.

Bug fixes :

  - One defense in depth patch. (BZ#639922)

  - Problems for certain SSL connections. In a reported
    case, this prevented the JBoss JAAS modules from
    connecting over SSL to Microsoft Active Directory
    servers. (BZ#642779)

All running instances of OpenJDK Java must be restarted for the update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=639922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=642779"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=1336
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa2b48f7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-1.6.0.0-1.31.b17.el6_0")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.31.b17.el6_0")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.31.b17.el6_0")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.31.b17.el6_0")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.31.b17.el6_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
