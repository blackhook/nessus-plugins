#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0976 and 
# CentOS Errata and Security Advisory 2008:0976 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43714);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-5012", "CVE-2008-5014", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5024", "CVE-2008-5052");
  script_bugtraq_id(32281);
  script_xref(name:"RHSA", value:"2008:0976");

  script_name(english:"CentOS 4 / 5 : thunderbird (CESA-2008:0976)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated thunderbird packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed HTML mail
content. An HTML mail message containing malicious content could cause
Thunderbird to crash or, potentially, execute arbitrary code as the
user running Thunderbird. (CVE-2008-5014, CVE-2008-5016,
CVE-2008-5017, CVE-2008-5018, CVE-2008-5021)

Several flaws were found in the way malformed HTML mail content was
processed. An HTML mail message containing specially crafted content
could potentially trick a Thunderbird user into surrendering sensitive
information. (CVE-2008-5012, CVE-2008-5022, CVE-2008-5024)

All Thunderbird users should upgrade to these updated packages, which
resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015428.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65963379"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015429.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?753d8708"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015432.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66426f8b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015433.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21102f30"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015448.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bcdfd59d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 94, 189, 200, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"thunderbird-1.5.0.12-17.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"thunderbird-2.0.0.18-1.el5.centos")) flag++;


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
