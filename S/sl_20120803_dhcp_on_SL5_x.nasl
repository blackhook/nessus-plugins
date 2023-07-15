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
  script_id(61427);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-3571");

  script_name(english:"Scientific Linux Security Update : dhcp on SL5.x i386/x86_64 (20120803)");
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
"The Dynamic Host Configuration Protocol (DHCP) is a protocol that
allows individual devices on an IP network to get their own network
configuration information, including an IP address, a subnet mask, and
a broadcast address.

A denial of service flaw was found in the way the dhcpd daemon handled
zero-length client identifiers. A remote attacker could use this flaw
to send a specially crafted request to dhcpd, possibly causing it to
enter an infinite loop and consume an excessive amount of CPU time.
(CVE-2012-3571)

Users of DHCP should upgrade to these updated packages, which contain
a backported patch to correct this issue. After installing this
update, all DHCP servers will be restarted automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1208&L=scientific-linux-errata&T=0&P=997
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc294e00"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dhcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libdhcp4client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libdhcp4client-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/06");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"dhclient-3.0.5-31.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"dhcp-3.0.5-31.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"dhcp-debuginfo-3.0.5-31.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"dhcp-devel-3.0.5-31.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"libdhcp4client-3.0.5-31.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"libdhcp4client-devel-3.0.5-31.el5_8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhclient / dhcp / dhcp-debuginfo / dhcp-devel / libdhcp4client / etc");
}
