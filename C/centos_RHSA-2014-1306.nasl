#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1306 and 
# CentOS Errata and Security Advisory 2014:1306 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77879);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187");
  script_bugtraq_id(70137, 70152, 70154);
  script_xref(name:"RHSA", value:"2014:1306");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");

  script_name(english:"CentOS 5 / 6 / 7 : bash (CESA-2014:1306)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated bash packages that fix one security issue are now available
for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The GNU Bourne Again shell (Bash) is a shell and command language
interpreter compatible with the Bourne shell (sh). Bash is the default
shell for Red Hat Enterprise Linux.

It was found that the fix for CVE-2014-6271 was incomplete, and Bash
still allowed certain characters to be injected into other
environments via specially crafted environment variables. An attacker
could potentially use this flaw to override or bypass environment
restrictions to execute shell commands. Certain services and
applications allow remote unauthenticated attackers to provide
environment variables, allowing them to exploit this issue.
(CVE-2014-7169)

Applications which directly create bash functions as environment
variables need to be made aware of changes to the way names are
handled by this update. For more information see the Knowledgebase
article at https://access.redhat.com/articles/1200223

Note: Docker users are advised to use 'yum update' within their
containers, and to commit the resulting changes.

For additional information on CVE-2014-6271 and CVE-2014-7169, refer
to the aforementioned Knowledgebase article.

All bash users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue.");
  # http://lists.centos.org/pipermail/centos-announce/2014-September/020593.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e6f3298");
  # http://lists.centos.org/pipermail/centos-announce/2014-September/020592.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7dcec836");
  # http://lists.centos.org/pipermail/centos-announce/2014-September/020651.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d96a66d4");
  script_set_attribute(attribute:"solution", value:
"Update the affected bash packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bash-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/CentOS/release");
if (! version) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (ereg(string:version, pattern:"release 5\.([0-9]([^0-9]|$)|10([^0-9]|$))", icase: 1))
{
  #CentOS release 5.0-5.10
  if (rpm_check(release:"CentOS-5", reference:"bash-3.2-33.el5_10.4")) flag++;
}
else 
{
  #CentOS release 5.11
  if (rpm_check(release:"CentOS-5", reference:"bash-3.2-33.el5_11.4")) flag++;
}

if (rpm_check(release:"CentOS-6", reference:"bash-4.1.2-15.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bash-doc-4.1.2-15.el6_5.2")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bash-4.2.45-5.el7_0.4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bash-doc-4.2.45-5.el7_0.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
