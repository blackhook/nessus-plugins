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
  script_id(60557);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-0784");

  script_name(english:"Scientific Linux Security Update : systemtap on SL4.x, SL5.x i386/x86_64");
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
"A race condition was discovered in SystemTap that could allow users in
the stapusr group to elevate privileges to that of members of the
stapdev group (and hence root), bypassing directory confinement
restrictions and allowing them to insert arbitrary SystemTap kernel
modules. (CVE-2009-0784)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0904&L=scientific-linux-errata&T=0&P=1336
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?617d7b7d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
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
if (rpm_check(release:"SL4", cpu:"i386", reference:"systemtap-0.6.2-2.el4_7")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"systemtap-0.6.2-2")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"systemtap-runtime-0.6.2-2.el4_7")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"systemtap-runtime-0.6.2-2")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"systemtap-testsuite-0.6.2-2.el4_7")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"systemtap-testsuite-0.6.2-2")) flag++;

if (rpm_check(release:"SL5", reference:"systemtap-0.7.2-3.el5_3")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-client-0.7.2-3.el5_3")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-runtime-0.7.2-3.el5_3")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-server-0.7.2-3.el5_3")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-testsuite-0.7.2-3.el5_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
