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
  script_id(60590);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1581");

  script_name(english:"Scientific Linux Security Update : squirrelmail on SL3.x, SL4.x, SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A server-side code injection flaw was found in the SquirrelMail
'map_yp_alias' function. If SquirrelMail was configured to retrieve a
user's IMAP server address from a Network Information Service (NIS)
server via the 'map_yp_alias' function, an unauthenticated, remote
attacker using a specially crafted username could use this flaw to
execute arbitrary code with the privileges of the web server.
(CVE-2009-1579)

Multiple cross-site scripting (XSS) flaws were found in SquirrelMail.
An attacker could construct a carefully crafted URL, which once
visited by an unsuspecting user, could cause the user's web browser to
execute malicious script in the context of the visited SquirrelMail
web page. (CVE-2009-1578)

It was discovered that SquirrelMail did not properly sanitize
Cascading Style Sheets (CSS) directives used in HTML mail. A remote
attacker could send a specially crafted email that could place mail
content above SquirrelMail's controls, possibly allowing phishing and
cross-site scripting attacks. (CVE-2009-1581)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0905&L=scientific-linux-errata&T=0&P=2031
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13ecbedc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(79, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/26");
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
if (rpm_check(release:"SL3", reference:"squirrelmail-1.4.8-13.el3")) flag++;

if (rpm_check(release:"SL4", reference:"squirrelmail-1.4.8-5.el4_8.5")) flag++;

if (rpm_check(release:"SL5", reference:"squirrelmail-1.4.8-5.el5_3.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
