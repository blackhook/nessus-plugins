#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1293 and 
# CentOS Errata and Security Advisory 2014:1293 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77835);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2014-6271");
  script_xref(name:"RHSA", value:"2014:1293");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"CentOS 5 / 6 / 7 : bash (CESA-2014:1293) (Shellshock)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated bash packages that fix one security issue are now available
for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Critical
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The GNU Bourne Again shell (Bash) is a shell and command language
interpreter compatible with the Bourne shell (sh). Bash is the default
shell for Red Hat Enterprise Linux.

A flaw was found in the way Bash evaluated certain specially crafted
environment variables. An attacker could use this flaw to override or
bypass environment restrictions to execute shell commands. Certain
services and applications allow remote unauthenticated attackers to
provide environment variables, allowing them to exploit this issue.
(CVE-2014-6271)

For additional information on the CVE-2014-6271 flaw, refer to the
Knowledgebase article at https://access.redhat.com/articles/1200223

Red Hat would like to thank Stephane Chazelas for reporting this
issue.

All bash users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue.");
  # https://lists.centos.org/pipermail/centos-announce/2014-September/020582.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?218f06b1");
  # https://lists.centos.org/pipermail/centos-announce/2014-September/020583.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f85a2dec");
  # https://lists.centos.org/pipermail/centos-announce/2014-September/020585.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93307af1");
  # https://lists.centos.org/pipermail/centos-announce/2014-September/020650.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3adf2ea1");
  script_set_attribute(attribute:"solution", value:
"Update the affected bash packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6271");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Qmail SMTP Bash Environment Variable Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bash-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"bash-3.2-33.el5.1")) flag++;

if (rpm_check(release:"CentOS-6", reference:"bash-4.1.2-15.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bash-doc-4.1.2-15.el6_5.1")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bash-4.2.45-5.el7_0.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bash-doc-4.2.45-5.el7_0.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bash / bash-doc");
}
