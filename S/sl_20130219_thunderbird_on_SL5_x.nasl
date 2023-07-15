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
  script_id(64779);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0780", "CVE-2013-0782", "CVE-2013-0783");

  script_name(english:"Scientific Linux Security Update : thunderbird on SL5.x, SL6.x i386/x86_64 (20130219)");
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
"Several flaws were found in the processing of malformed content.
Malicious content could cause Thunderbird to crash or, potentially,
execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2013-0775, CVE-2013-0780, CVE-2013-0782,
CVE-2013-0783)

It was found that, after canceling a proxy server's authentication
prompt, the address bar continued to show the requested site's
address. An attacker could use this flaw to conduct phishing attacks
by tricking a user into believing they are viewing trusted content.
(CVE-2013-0776)

Note: All issues cannot be exploited by a specially crafted HTML mail
message as JavaScript is disabled by default for mail messages. They
could be exploited another way in Thunderbird, for example, when
viewing the full remote content of an RSS feed.

Important: This erratum upgrades Thunderbird to version 17.0.3 ESR.
Thunderbird 17 is not completely backwards-compatible with all Mozilla
add-ons and Thunderbird plug-ins that worked with Thunderbird 10.0.
Thunderbird 17 checks compatibility on first-launch, and, depending on
the individual configuration and the installed add-ons and plug-ins,
may disable said Add-ons and plug-ins, or attempt to check for updates
and upgrade them. Add-ons and plug-ins may have to be manually
updated.

After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=3210
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa7b68b5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
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
if (rpm_check(release:"SL5", reference:"thunderbird-17.0.3-1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"thunderbird-debuginfo-17.0.3-1.el5_9")) flag++;

if (rpm_check(release:"SL6", reference:"thunderbird-17.0.3-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"thunderbird-debuginfo-17.0.3-1.el6_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
}
