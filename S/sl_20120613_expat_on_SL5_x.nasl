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
  script_id(61327);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-0876", "CVE-2012-1148");

  script_name(english:"Scientific Linux Security Update : expat on SL5.x, SL6.x i386/x86_64 (20120613)");
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
"Expat is a C library written by James Clark for parsing XML documents.

A denial of service flaw was found in the implementation of hash
arrays in Expat. An attacker could use this flaw to make an
application using Expat consume an excessive amount of CPU time by
providing a specially crafted XML file that triggers multiple hash
function collisions. To mitigate this issue, randomization has been
added to the hash function to reduce the chance of an attacker
successfully causing intentional collisions. (CVE-2012-0876)

A memory leak flaw was found in Expat. If an XML file processed by an
application linked against Expat triggered a memory re-allocation
failure, Expat failed to free the previously allocated memory. This
could cause the application to exit unexpectedly or crash when all
available memory is exhausted. (CVE-2012-1148)

All Expat users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, applications using the Expat library must be
restarted for the update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1206&L=scientific-linux-errata&T=0&P=1553
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ad05e00"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected expat, expat-debuginfo and / or expat-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:expat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:expat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:expat-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/13");
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
if (rpm_check(release:"SL5", reference:"expat-1.95.8-11.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"expat-debuginfo-1.95.8-11.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"expat-devel-1.95.8-11.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"expat-2.0.1-11.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"expat-debuginfo-2.0.1-11.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"expat-devel-2.0.1-11.el6_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "expat / expat-debuginfo / expat-devel");
}
