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
  script_id(90502);
  script_version("2.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2114", "CVE-2016-2115", "CVE-2016-2118");

  script_name(english:"Scientific Linux Security Update : samba and samba4 on SL6.x, SL7.x i386/x86_64 (20160412) (Badlock)");
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

  - It was found that Samba did not validate SSL/TLS
    certificates in certain connections. A man-in-the-middle
    attacker could use this flaw to spoof a Samba server
    using a specially crafted SSL/TLS certificate.
    (CVE-2016-2113)

  - It was discovered that Samba did not enforce Server
    Message Block (SMB) signing for clients using the SMB1
    protocol. A man-in-the-middle attacker could use this
    flaw to modify traffic between a client and a server.
    (CVE-2016-2114)

  - It was found that Samba did not enable integrity
    protection for IPC traffic by default. A
    man-in-the-middle attacker could use this flaw to view
    and modify the data sent between a Samba server and a
    client. (CVE-2016-2115)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1604&L=scientific-linux-errata&F=&S=&P=8117
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2747865e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ldb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libldb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtalloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtalloc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtevent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtevent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openchange");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openchange-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openchange-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openchange-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openchange-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pyldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pyldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pytalloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pytalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-tdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-tevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tdb-tools");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"ipa-admintools-3.0.0-47.el6_7.2")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-client-3.0.0-47.el6_7.2")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-debuginfo-3.0.0-47.el6_7.2")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-python-3.0.0-47.el6_7.2")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-server-3.0.0-47.el6_7.2")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-server-selinux-3.0.0-47.el6_7.2")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-server-trust-ad-3.0.0-47.el6_7.2")) flag++;
if (rpm_check(release:"SL6", reference:"ldb-tools-1.1.25-2.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libldb-1.1.25-2.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libldb-debuginfo-1.1.25-2.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libldb-devel-1.1.25-2.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libtalloc-2.1.5-1.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libtalloc-debuginfo-2.1.5-1.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libtalloc-devel-2.1.5-1.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libtdb-1.3.8-1.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libtdb-debuginfo-1.3.8-1.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libtdb-devel-1.3.8-1.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libtevent-0.9.26-2.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libtevent-debuginfo-0.9.26-2.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libtevent-devel-0.9.26-2.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"openchange-1.0-7.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"openchange-client-1.0-7.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"openchange-debuginfo-1.0-7.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"openchange-devel-1.0-7.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"openchange-devel-docs-1.0-7.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"pyldb-1.1.25-2.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"pyldb-devel-1.1.25-2.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"pytalloc-2.1.5-1.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"pytalloc-devel-2.1.5-1.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"python-tdb-1.3.8-1.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"python-tevent-0.9.26-2.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-4.2.10-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-client-4.2.10-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-common-4.2.10-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-dc-4.2.10-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-dc-libs-4.2.10-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-debuginfo-4.2.10-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-devel-4.2.10-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-libs-4.2.10-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-pidl-4.2.10-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-python-4.2.10-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-test-4.2.10-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-4.2.10-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-clients-4.2.10-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-krb5-locator-4.2.10-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"tdb-tools-1.3.8-1.el6_7")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-admintools-4.2.0-15.el7_2.6.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-client-4.2.0-15.el7_2.6.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-debuginfo-4.2.0-15.el7_2.6.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-python-4.2.0-15.el7_2.6.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-4.2.0-15.el7_2.6.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-dns-4.2.0-15.el7_2.6.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.2.0-15.el7_2.6.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ldb-tools-1.1.25-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libldb-1.1.25-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libldb-debuginfo-1.1.25-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libldb-devel-1.1.25-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsmbclient-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsmbclient-devel-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libtalloc-2.1.5-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libtalloc-debuginfo-2.1.5-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libtalloc-devel-2.1.5-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libtdb-1.3.8-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libtdb-debuginfo-1.3.8-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libtdb-devel-1.3.8-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libtevent-0.9.26-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libtevent-debuginfo-0.9.26-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libtevent-devel-0.9.26-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwbclient-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwbclient-devel-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openchange-2.0-10.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openchange-client-2.0-10.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openchange-debuginfo-2.0-10.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openchange-devel-2.0-10.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"openchange-devel-docs-2.0-10.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pyldb-1.1.25-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pyldb-devel-1.1.25-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pytalloc-2.1.5-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pytalloc-devel-2.1.5-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-tdb-1.3.8-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-tevent-0.9.26-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-client-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-client-libs-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"samba-common-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-common-libs-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-common-tools-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-dc-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-dc-libs-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-debuginfo-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-devel-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-libs-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"samba-pidl-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-python-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-test-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-test-devel-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-test-libs-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-vfs-glusterfs-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-clients-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-krb5-locator-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-modules-4.2.10-6.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tdb-tools-1.3.8-1.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-admintools / ipa-client / ipa-debuginfo / ipa-python / etc");
}
