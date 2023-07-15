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
  script_id(60556);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-6123");

  script_name(english:"Scientific Linux Security Update : net-snmp on SL3.x i386/x86_64");
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
"It was discovered that the snmpd daemon did not use TCP wrappers
correctly, causing network hosts access restrictions defined in
'/etc/hosts.allow' and '/etc/hosts.deny' to not be honored. A remote
attacker could use this flaw to bypass intended access restrictions.
(CVE-2008-6123)

This issue only affected configurations where hosts.allow and
hosts.deny were used to limit access to the SNMP server. To obtain
information from the server, the attacker would have to successfully
authenticate, usually by providing a correct community string.

After installing the update, the snmpd and snmptrapd daemons will be
restarted automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0903&L=scientific-linux-errata&T=0&P=3122
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?93272dfa"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(20);

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
if (rpm_check(release:"SL3", reference:"net-snmp-5.0.9-2.30E.27")) flag++;
if (rpm_check(release:"SL3", reference:"net-snmp-devel-5.0.9-2.30E.27")) flag++;
if (rpm_check(release:"SL3", reference:"net-snmp-libs-5.0.9-2.30E.27")) flag++;
if (rpm_check(release:"SL3", reference:"net-snmp-perl-5.0.9-2.30E.27")) flag++;
if (rpm_check(release:"SL3", reference:"net-snmp-utils-5.0.9-2.30E.27")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");