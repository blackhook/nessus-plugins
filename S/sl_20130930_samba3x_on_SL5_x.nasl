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
  script_id(70390);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0213", "CVE-2013-0214", "CVE-2013-4124");

  script_name(english:"Scientific Linux Security Update : samba3x on SL5.x i386/x86_64 (20130930)");
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
"It was discovered that the Samba Web Administration Tool (SWAT) did
not protect against being opened in a web page frame. A remote
attacker could possibly use this flaw to conduct a clickjacking attack
against SWAT users or users with an active SWAT session.
(CVE-2013-0213)

A flaw was found in the Cross-Site Request Forgery (CSRF) protection
mechanism implemented in SWAT. An attacker with the knowledge of a
victim's password could use this flaw to bypass CSRF protections and
conduct a CSRF attack against the victim SWAT user. (CVE-2013-0214)

An integer overflow flaw was found in the way Samba handled an
Extended Attribute (EA) list provided by a client. A malicious client
could send a specially crafted EA list that triggered an overflow,
causing the server to loop and reprocess the list using an excessive
amount of memory. (CVE-2013-4124)

Note: This issue did not affect the default configuration of the Samba
server.

After installing this update, the smb service will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1310&L=scientific-linux-errata&T=0&P=683
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbd14410"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtalloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtalloc-compat1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtevent-devel");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/11");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"libtalloc-2.0.7-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libtalloc-compat1-2.0.7-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libtalloc-devel-2.0.7-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libtevent-0.9.18-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libtevent-devel-0.9.18-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-3.6.6-0.136.el5")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-client-3.6.6-0.136.el5")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-common-3.6.6-0.136.el5")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-debuginfo-3.6.6-0.136.el5")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-doc-3.6.6-0.136.el5")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-domainjoin-gui-3.6.6-0.136.el5")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-swat-3.6.6-0.136.el5")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-winbind-3.6.6-0.136.el5")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-winbind-devel-3.6.6-0.136.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtalloc / libtalloc-compat1 / libtalloc-devel / libtevent / etc");
}
