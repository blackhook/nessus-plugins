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
  script_id(71341);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-4408", "CVE-2013-4475");

  script_name(english:"Scientific Linux Security Update : samba and samba3x on SL5.x, SL6.x i386/x86_64 (20131210)");
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
"A heap-based buffer overflow flaw was found in the DCE-RPC client code
in Samba. A specially crafted DCE-RPC packet could cause various Samba
programs to crash or, possibly, execute arbitrary code when parsed. A
malicious or compromised Active Directory Domain Controller could use
this flaw to compromise the winbindd daemon running with root
privileges. (CVE-2013-4408)

A flaw was found in the way Samba performed ACL checks on alternate
file and directory data streams. An attacker able to access a CIFS
share with alternate stream support enabled could access alternate
data streams regardless of the underlying file or directory ACL
permissions. (CVE-2013-4475)

After installing this update, the smb service will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=3312
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a899e75"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-krb5-locator");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL5", reference:"samba3x-3.6.6-0.138.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-client-3.6.6-0.138.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-common-3.6.6-0.138.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-debuginfo-3.6.6-0.138.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-doc-3.6.6-0.138.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-domainjoin-gui-3.6.6-0.138.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-swat-3.6.6-0.138.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-winbind-3.6.6-0.138.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-winbind-devel-3.6.6-0.138.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"libsmbclient-3.6.9-167.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"libsmbclient-devel-3.6.9-167.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-3.6.9-167.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-client-3.6.9-167.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-common-3.6.9-167.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-debuginfo-3.6.9-167.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-doc-3.6.9-167.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-domainjoin-gui-3.6.9-167.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-swat-3.6.9-167.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-3.6.9-167.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-clients-3.6.9-167.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-devel-3.6.9-167.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-krb5-locator-3.6.9-167.el6_5")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
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
