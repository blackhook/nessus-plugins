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
  script_id(62493);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-1956", "CVE-2012-3982", "CVE-2012-3986", "CVE-2012-3988", "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-3992", "CVE-2012-3993", "CVE-2012-3994", "CVE-2012-3995", "CVE-2012-4179", "CVE-2012-4180", "CVE-2012-4181", "CVE-2012-4182", "CVE-2012-4183", "CVE-2012-4184", "CVE-2012-4185", "CVE-2012-4186", "CVE-2012-4187", "CVE-2012-4188");

  script_name(english:"Scientific Linux Security Update : thunderbird on SL5.x, SL6.x i386/x86_64 (20121009)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed content.
Malicious content could cause Thunderbird to crash or, potentially,
execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2012-3982, CVE-2012-3988, CVE-2012-3990,
CVE-2012-3995, CVE-2012-4179, CVE-2012-4180, CVE-2012-4181,
CVE-2012-4182, CVE-2012-4183, CVE-2012-4185, CVE-2012-4186,
CVE-2012-4187, CVE-2012-4188)

Two flaws in Thunderbird could allow malicious content to bypass
intended restrictions, possibly leading to information disclosure, or
Thunderbird executing arbitrary code. Note that the information
disclosure issue could possibly be combined with other flaws to
achieve arbitrary code execution. (CVE-2012-3986, CVE-2012-3991)

Multiple flaws were found in the location object implementation in
Thunderbird. Malicious content could be used to perform cross-site
scripting attacks, script injection, or spoofing attacks.
(CVE-2012-1956, CVE-2012-3992, CVE-2012-3994)

Two flaws were found in the way Chrome Object Wrappers were
implemented. Malicious content could be used to perform cross-site
scripting attacks or cause Thunderbird to execute arbitrary code.
(CVE-2012-3993, CVE-2012-4184)

Note: None of the issues in this advisory can be exploited by a
specially crafted HTML mail message as JavaScript is disabled by
default for mail messages. They could be exploited another way in
Thunderbird, for example, when viewing the full remote content of an
RSS feed.

After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1210&L=scientific-linux-errata&T=0&P=1502
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4796b444"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 5.0 - 15.0.1 __exposedProps__ XCS Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/11");
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
if (rpm_check(release:"SL5", reference:"thunderbird-10.0.8-1.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"thunderbird-10.0.8-1.el6_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
