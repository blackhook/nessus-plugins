#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0544 and 
# CentOS Errata and Security Advisory 2010:0544 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(48266);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-0174", "CVE-2010-0175", "CVE-2010-0176", "CVE-2010-0177", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1211", "CVE-2010-1214", "CVE-2010-2753", "CVE-2010-2754");
  script_bugtraq_id(39079, 39122, 39123, 39128, 39133, 41082, 41090, 41102, 41103, 41824);
  script_xref(name:"RHSA", value:"2010:0544");

  script_name(english:"CentOS 4 : thunderbird (CESA-2010:0544)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated thunderbird package that fixes several security issues is
now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed HTML mail
content. An HTML mail message containing malicious content could cause
Thunderbird to crash or, potentially, execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2010-0174,
CVE-2010-1200, CVE-2010-1211, CVE-2010-1214, CVE-2010-2753)

An integer overflow flaw was found in the processing of malformed HTML
mail content. An HTML mail message containing malicious content could
cause Thunderbird to crash or, potentially, execute arbitrary code
with the privileges of the user running Thunderbird. (CVE-2010-1199)

Several use-after-free flaws were found in Thunderbird. Viewing an
HTML mail message containing malicious content could result in
Thunderbird executing arbitrary code with the privileges of the user
running Thunderbird. (CVE-2010-0175, CVE-2010-0176, CVE-2010-0177)

A flaw was found in the way Thunderbird plug-ins interact. It was
possible for a plug-in to reference the freed memory from a different
plug-in, resulting in the execution of arbitrary code with the
privileges of the user running Thunderbird. (CVE-2010-1198)

A flaw was found in the way Thunderbird handled the
'Content-Disposition: attachment' HTTP header when the 'Content-Type:
multipart' HTTP header was also present. Loading remote HTTP content
that allows arbitrary uploads and relies on the 'Content-Disposition:
attachment' HTTP header to prevent content from being displayed
inline, could be used by an attacker to serve malicious content to
users. (CVE-2010-1197)

A same-origin policy bypass flaw was found in Thunderbird. Remote HTML
content could steal private data from different remote HTML content
Thunderbird has loaded. (CVE-2010-2754)

All Thunderbird users should upgrade to this updated package, which
resolves these issues. All running instances of Thunderbird must be
restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016886.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd6a7453"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016887.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?447c8e61"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"thunderbird-1.5.0.12-28.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"thunderbird-1.5.0.12-28.el4.centos")) flag++;


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
