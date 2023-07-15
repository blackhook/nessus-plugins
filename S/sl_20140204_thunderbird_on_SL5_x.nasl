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
  script_id(72323);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-1477", "CVE-2014-1479", "CVE-2014-1481", "CVE-2014-1482", "CVE-2014-1486", "CVE-2014-1487");

  script_name(english:"Scientific Linux Security Update : thunderbird on SL5.x, SL6.x i386/x86_64 (20140204)");
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
Thunderbird. (CVE-2014-1477, CVE-2014-1482, CVE-2014-1486)

A flaw was found in the way Thunderbird handled error messages related
to web workers. An attacker could use this flaw to bypass the
same-origin policy, which could lead to cross-site scripting (XSS)
attacks, or could potentially be used to gather authentication tokens
and other data from third-party websites. (CVE-2014-1487)

A flaw was found in the implementation of System Only Wrappers (SOW).
An attacker could use this flaw to crash Thunderbird. When combined
with other vulnerabilities, this flaw could have additional security
implications. (CVE-2014-1479)

It was found that the Thunderbird JavaScript engine incorrectly
handled window objects. A remote attacker could use this flaw to
bypass certain security checks and possibly execute arbitrary code.
(CVE-2014-1481)

Note: All of the above issues cannot be exploited by a specially
crafted HTML mail message as JavaScript is disabled by default for
mail messages. They could be exploited another way in Thunderbird, for
example, when viewing the full remote content of an RSS feed.

After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1402&L=scientific-linux-errata&T=0&P=688
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44120b97"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL5", reference:"thunderbird-24.3.0-2.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"thunderbird-debuginfo-24.3.0-2.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"thunderbird-24.3.0-2.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"thunderbird-debuginfo-24.3.0-2.el6_5")) flag++;


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
