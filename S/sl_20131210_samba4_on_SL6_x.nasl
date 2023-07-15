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
  script_id(71340);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-4408");

  script_name(english:"Scientific Linux Security Update : samba4 on SL6.x i386/x86_64 (20131210)");
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

After installing this update, the smb service will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=3590
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3d52057"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
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
if (rpm_check(release:"SL6", reference:"samba4-4.0.0-60.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-client-4.0.0-60.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-common-4.0.0-60.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-dc-4.0.0-60.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-dc-libs-4.0.0-60.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-debuginfo-4.0.0-60.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-devel-4.0.0-60.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-libs-4.0.0-60.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-pidl-4.0.0-60.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-python-4.0.0-60.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-swat-4.0.0-60.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-test-4.0.0-60.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-4.0.0-60.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-clients-4.0.0-60.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-krb5-locator-4.0.0-60.el6_5.rc4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba4 / samba4-client / samba4-common / samba4-dc / samba4-dc-libs / etc");
}
