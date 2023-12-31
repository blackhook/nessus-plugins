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
  script_id(60612);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-1889");

  script_name(english:"Scientific Linux Security Update : pidgin on SL4.x, SL5.x i386/x86_64");
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
"A denial of service flaw was found in the Pidgin OSCAR protocol
implementation. If a remote ICQ user sent a web message to a local
Pidgin user using this protocol, it would cause excessive memory
usage, leading to a denial of service (Pidgin crash). (CVE-2009-1889)

These updated packages also fix the following bug :

  - the Yahoo! Messenger Protocol changed, making it
    incompatible (and unusable) with Pidgin versions prior
    to 2.5.7. This update provides Pidgin 2.5.8, which
    implements version 16 of the Yahoo! Messenger Protocol,
    which resolves this issue.

Note: These packages upgrade Pidgin to version 2.5.8.

Pidgin must be restarted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0907&L=scientific-linux-errata&T=0&P=322
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b397c48"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/02");
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
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL4", reference:"finch-2.5.8-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"finch-devel-2.5.8-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-2.5.8-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-devel-2.5.8-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-perl-2.5.8-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-tcl-2.5.8-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-2.5.8-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-devel-2.5.8-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-perl-2.5.8-1.el4")) flag++;

if (rpm_check(release:"SL5", reference:"finch-2.5.8-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"finch-devel-2.5.8-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-2.5.8-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-devel-2.5.8-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-perl-2.5.8-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-tcl-2.5.8-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-2.5.8-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-devel-2.5.8-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-perl-2.5.8-1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
