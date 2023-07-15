#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1211 and 
# CentOS Errata and Security Advisory 2012:1211 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(61722);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-1970", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974", "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-3956", "CVE-2012-3957", "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960", "CVE-2012-3961", "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964", "CVE-2012-3966", "CVE-2012-3967", "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970", "CVE-2012-3972", "CVE-2012-3978", "CVE-2012-3980");
  script_xref(name:"RHSA", value:"2012:1211");

  script_name(english:"CentOS 5 / 6 : thunderbird (CESA-2012:1211)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing a security update."
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
Thunderbird. (CVE-2012-1970, CVE-2012-1972, CVE-2012-1973,
CVE-2012-1974, CVE-2012-1975, CVE-2012-1976, CVE-2012-3956,
CVE-2012-3957, CVE-2012-3958, CVE-2012-3959, CVE-2012-3960,
CVE-2012-3961, CVE-2012-3962, CVE-2012-3963, CVE-2012-3964)

Content containing a malicious Scalable Vector Graphics (SVG) image
file could cause Thunderbird to crash or, potentially, execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2012-3969, CVE-2012-3970)

Two flaws were found in the way Thunderbird rendered certain images
using WebGL. Malicious content could cause Thunderbird to crash or,
under certain conditions, possibly execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2012-3967,
CVE-2012-3968)

A flaw was found in the way Thunderbird decoded embedded bitmap images
in Icon Format (ICO) files. Content containing a malicious ICO file
could cause Thunderbird to crash or, under certain conditions,
possibly execute arbitrary code with the privileges of the user
running Thunderbird. (CVE-2012-3966)

A flaw was found in the way the 'eval' command was handled by the
Thunderbird Error Console. Running 'eval' in the Error Console while
viewing malicious content could possibly cause Thunderbird to execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2012-3980)

An out-of-bounds memory read flaw was found in the way Thunderbird
used the format-number feature of XSLT (Extensible Stylesheet Language
Transformations). Malicious content could possibly cause an
information leak, or cause Thunderbird to crash. (CVE-2012-3972)

A flaw was found in the location object implementation in Thunderbird.
Malicious content could use this flaw to possibly allow restricted
content to be loaded. (CVE-2012-3978)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Gary Kwong, Christian Holler, Jesse
Ruderman, John Schoenick, Vladimir Vukicevic, Daniel Holbert, Abhishek
Arya, Frederic Hoguin, miaubiz, Arthur Gerkis, Nicolas Gregoire,
moz_bug_r_a4, and Colby Russell as the original reporters of these
issues.

Note: All issues except CVE-2012-3969 and CVE-2012-3970 cannot be
exploited by a specially crafted HTML mail message as JavaScript is
disabled by default for mail messages. They could be exploited another
way in Thunderbird, for example, when viewing the full remote content
of an RSS feed.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 10.0.7 ESR, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-August/018833.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9c94ad9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-August/018835.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9f6a870"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1970");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"thunderbird-10.0.7-1.el5.centos", allowmaj:TRUE)) flag++;

if (rpm_check(release:"CentOS-6", reference:"thunderbird-10.0.7-1.el6.centos", allowmaj:TRUE)) flag++;


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
