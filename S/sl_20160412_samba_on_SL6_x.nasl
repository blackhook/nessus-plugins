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
  script_id(90504);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-5370", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2115", "CVE-2016-2118");

  script_name(english:"Scientific Linux Security Update : samba on SL6.x i386/x86_64 (20160412) (Badlock)");
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
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1604&L=scientific-linux-errata&F=&S=&P=7302
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98da124b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-krb5-locator");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"libsmbclient-3.6.23-30.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libsmbclient-devel-3.6.23-30.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba-3.6.23-30.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba-client-3.6.23-30.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba-common-3.6.23-30.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba-debuginfo-3.6.23-30.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba-doc-3.6.23-30.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba-domainjoin-gui-3.6.23-30.el6_7")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"samba-glusterfs-3.6.23-30.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba-swat-3.6.23-30.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-3.6.23-30.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-clients-3.6.23-30.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-devel-3.6.23-30.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-krb5-locator-3.6.23-30.el6_7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / samba / samba-client / etc");
}
