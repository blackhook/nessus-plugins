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
  script_id(61455);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-2668");

  script_name(english:"Scientific Linux Security Update : openldap on SL6.x i386/x86_64 (20120808)");
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
"It was found that the OpenLDAP server daemon ignored olcTLSCipherSuite
settings. This resulted in the default cipher suite always being used,
which could lead to weaker than expected ciphers being accepted during
Transport Layer Security (TLS) negotiation with OpenLDAP clients.
(CVE-2012-2668)

This update also fixes the following bug :

  - When the smbk5pwd overlay was enabled in an OpenLDAP
    server, and a user changed their password, the Microsoft
    NT LAN Manager (NTLM) and Microsoft LAN Manager (LM)
    hashes were not computed correctly. This led to the
    sambaLMPassword and sambaNTPassword attributes being
    updated with incorrect values, preventing the user
    logging in using a Windows-based client or a Samba
    client.

With this update, the smbk5pwd overlay is linked against OpenSSL. As
such, the NTLM and LM hashes are computed correctly, and password
changes work as expected when using smbk5pwd. (BZ#844428)

After installing this update, the OpenLDAP daemons will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=844428"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1208&L=scientific-linux-errata&T=0&P=1123
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab8d6b6b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/09");
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
if (rpm_check(release:"SL6", reference:"openldap-2.4.23-26.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-clients-2.4.23-26.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-devel-2.4.23-26.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-servers-2.4.23-26.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-servers-sql-2.4.23-26.el6_3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openldap / openldap-clients / openldap-devel / openldap-servers / etc");
}
