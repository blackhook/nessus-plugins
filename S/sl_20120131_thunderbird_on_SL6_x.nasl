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
  script_id(61231);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-3659", "CVE-2011-3670", "CVE-2012-0442", "CVE-2012-0449");

  script_name(english:"Scientific Linux Security Update : thunderbird on SL6.x i386/x86_64 (20120131)");
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
"Mozilla Thunderbird is a standalone mail and newsgroup client.

A use-after-free flaw was found in the way Thunderbird removed
nsDOMAttribute child nodes. In certain circumstances, due to the
premature notification of AttributeChildRemoved, a malicious script
could possibly use this flaw to cause Thunderbird to crash or,
potentially, execute arbitrary code with the privileges of the user
running Thunderbird. (CVE-2011-3659)

Several flaws were found in the processing of malformed content. An
HTML mail message containing malicious content could cause Thunderbird
to crash or, potentially, execute arbitrary code with the privileges
of the user running Thunderbird. (CVE-2012-0442)

A flaw was found in the way Thunderbird parsed certain Scalable Vector
Graphics (SVG) image files that contained eXtensible Style Sheet
Language Transformations (XSLT). An HTML mail message containing a
malicious SVG image file could cause Thunderbird to crash or,
potentially, execute arbitrary code with the privileges of the user
running Thunderbird. (CVE-2012-0449)

The same-origin policy in Thunderbird treated http://example.com and
http://[example.com] as interchangeable. A malicious script could
possibly use this flaw to gain access to sensitive information (such
as a client's IP and user e-mail address, or httpOnly cookies) that
may be included in HTTP proxy error replies, generated in response to
invalid URLs using square brackets. (CVE-2011-3670)

Note: The CVE-2011-3659 and CVE-2011-3670 issues cannot be exploited
by a specially crafted HTML mail message as JavaScript is disabled by
default for mail messages. It could be exploited another way in
Thunderbird, for example, when viewing the full remote content of an
RSS feed.

For technical details regarding these flaws, refer to the Mozilla
security advisories for Thunderbird 3.1.18.

All Thunderbird users should upgrade to these updated packages, which
contain Thunderbird version 3.1.18, which corrects these issues. After
installing the update, Thunderbird must be restarted for the changes
to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=scientific-linux-errata&T=0&P=192
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f00640af"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 8/9 AttributeChildRemoved() Use-After-Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/31");
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
if (rpm_check(release:"SL6", reference:"thunderbird-3.1.18-1.el6_2", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SL6", reference:"thunderbird-debuginfo-3.1.18-1.el6_2", allowmaj:TRUE)) flag++;


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
