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
  script_id(90501);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2115", "CVE-2016-2118");

  script_name(english:"Scientific Linux Security Update : samba3x on SL5.x i386/x86_64 (20160412) (Badlock)");
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
"Security Fix(es) :

  - Multiple flaws were found in Samba's DCE/RPC protocol
    implementation. A remote, authenticated attacker could
    use these flaws to cause a denial of service against the
    Samba server (high CPU load or a crash) or, possibly,
    execute arbitrary code with the permissions of the user
    running Samba (root). This flaw could also be used to
    downgrade a secure DCE/RPC connection by a
    man-in-the-middle attacker taking control of an Active
    Directory (AD) object and compromising the security of a
    Samba Active Directory Domain Controller (DC).
    (CVE-2015-5370)

Note: While Samba packages as shipped in Scientific Linux do not
support running Samba as an AD DC, this flaw applies to all roles
Samba implements.

  - A protocol flaw, publicly referred to as Badlock, was
    found in the Security Account Manager Remote Protocol
    (MS-SAMR) and the Local Security Authority (Domain
    Policy) Remote Protocol (MS-LSAD). Any authenticated
    DCE/RPC connection that a client initiates against a
    server could be used by a man-in-the-middle attacker to
    impersonate the authenticated user against the SAMR or
    LSA service on the server. As a result, the attacker
    would be able to get read/write access to the Security
    Account Manager database, and use this to reveal all
    passwords or any other potentially sensitive information
    in that database. (CVE-2016-2118)

  - Several flaws were found in Samba's implementation of
    NTLMSSP authentication. An unauthenticated,
    man-in-the-middle attacker could use this flaw to clear
    the encryption and integrity flags of a connection,
    causing data to be transmitted in plain text. The
    attacker could also force the client or server into
    sending data in plain text even if encryption was
    explicitly requested for that connection.
    (CVE-2016-2110)

  - It was discovered that Samba configured as a Domain
    Controller would establish a secure communication
    channel with a machine using a spoofed computer name. A
    remote attacker able to observe network traffic could
    use this flaw to obtain session-related information
    about the spoofed machine. (CVE-2016-2111)

  - It was found that Samba's LDAP implementation did not
    enforce integrity protection for LDAP connections. A
    man-in-the-middle attacker could use this flaw to
    downgrade LDAP connections to use no integrity
    protection, allowing them to hijack such connections.
    (CVE-2016-2112)

  - It was found that Samba did not enable integrity
    protection for IPC traffic by default. A
    man-in-the-middle attacker could use this flaw to view
    and modify the data sent between a Samba server and a
    client. (CVE-2016-2115)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1604&L=scientific-linux-errata&F=&S=&P=6491
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bab64414"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba3x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba3x-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba3x-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba3x-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba3x-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba3x-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba3x-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba3x-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba3x-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"samba3x-3.6.23-12.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-client-3.6.23-12.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-common-3.6.23-12.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-debuginfo-3.6.23-12.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-doc-3.6.23-12.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-domainjoin-gui-3.6.23-12.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-swat-3.6.23-12.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-winbind-3.6.23-12.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-winbind-devel-3.6.23-12.el5_11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba3x / samba3x-client / samba3x-common / samba3x-debuginfo / etc");
}
