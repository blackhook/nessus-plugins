#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0388. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58339);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-0451", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457", "CVE-2012-0458", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0461", "CVE-2012-0462", "CVE-2012-0464");
  script_bugtraq_id(52456, 52457, 52458, 52459, 52460, 52461, 52463, 52464, 52465, 52467);
  script_xref(name:"RHSA", value:"2012:0388");

  script_name(english:"RHEL 5 / 6 : thunderbird (RHSA-2012:0388)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An updated thunderbird package that fixes multiple security issues is
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed content.
Malicious content could cause Thunderbird to crash or, potentially,
execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2012-0461, CVE-2012-0462, CVE-2012-0464)

Two flaws were found in the way Thunderbird parsed certain Scalable
Vector Graphics (SVG) image files. An HTML mail message containing a
malicious SVG image file could cause an information leak, or cause
Thunderbird to crash or, potentially, execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2012-0456,
CVE-2012-0457)

A flaw could allow malicious content to bypass intended restrictions,
possibly leading to a cross-site scripting (XSS) attack if a user were
tricked into dropping a 'javascript:' link onto a frame.
(CVE-2012-0455)

It was found that the home page could be set to a 'javascript:' link.
If a user were tricked into setting such a home page by dragging a
link to the home button, it could cause Firefox to repeatedly crash,
eventually leading to arbitrary code execution with the privileges of
the user running Firefox. A similar flaw was found and fixed in
Thunderbird. (CVE-2012-0458)

A flaw was found in the way Thunderbird parsed certain, remote content
containing 'cssText'. Malicious, remote content could cause
Thunderbird to crash or, potentially, execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2012-0459)

It was found that by using the DOM fullscreen API, untrusted content
could bypass the mozRequestFullscreen security protections. Malicious
content could exploit this API flaw to cause user interface spoofing.
(CVE-2012-0460)

A flaw was found in the way Thunderbird handled content with multiple
Content Security Policy (CSP) headers. This could lead to a cross-site
scripting attack if used in conjunction with a website that has a
header injection flaw. (CVE-2012-0451)

Note: All issues except CVE-2012-0456 and CVE-2012-0457 cannot be
exploited by a specially crafted HTML mail message as JavaScript is
disabled by default for mail messages. It could be exploited another
way in Thunderbird, for example, when viewing the full remote content
of an RSS feed.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 10.0.3 ESR, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2012:0388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-0451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-0455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-0457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-0456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-0459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-0458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-0460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-0461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-0462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-0464"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0388";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"thunderbird-10.0.3-1.el5_8", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"thunderbird-10.0.3-1.el5_8", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"thunderbird-debuginfo-10.0.3-1.el5_8", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"thunderbird-debuginfo-10.0.3-1.el5_8", allowmaj:TRUE)) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"thunderbird-10.0.3-1.el6_2", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"thunderbird-10.0.3-1.el6_2", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"thunderbird-10.0.3-1.el6_2", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"thunderbird-debuginfo-10.0.3-1.el6_2", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"thunderbird-debuginfo-10.0.3-1.el6_2", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"thunderbird-debuginfo-10.0.3-1.el6_2", allowmaj:TRUE)) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
  }
}
