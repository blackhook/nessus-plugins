#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1311. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79052);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187");
  script_bugtraq_id(70137, 70152, 70154);
  script_xref(name:"RHSA", value:"2014:1311");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");

  script_name(english:"RHEL 4 / 5 / 6 : bash (RHSA-2014:1311)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"[Updated September 30, 2014] This advisory has been updated with
information on restarting system services after applying this update.
No changes have been made to the original packages.

Updated bash packages that fix one security issue are now available
for Red Hat Enterprise Linux 4 Extended Life Cycle Support, Red Hat
Enterprise Linux 5.6 Long Life, Red Hat Enterprise Linux 5.9 Extended
Update Support, Red Hat Enterprise Linux 6.2 Advanced Update Support,
and Red Hat Enterprise Linux 6.4 Extended Update Support.

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
handled by this update. Note that certain services, screen sessions,
and tmux sessions may need to be restarted, and affected interactive
users may need to re-login. Installing these updated packages without
restarting services will address the vulnerability, but functionality
may be impacted until affected services are restarted. For more
information see the Knowledgebase article at
https://access.redhat.com/articles/1200223

Note: Docker users are advised to use 'yum update' within their
containers, and to commit the resulting changes.

For additional information on CVE-2014-6271 and CVE-2014-7169, refer
to the aforementioned Knowledgebase article.

All bash users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/1200223");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2014:1311");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2014-7169");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2014-7186");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2014-7187");
  script_set_attribute(attribute:"solution", value:
"Update the affected bash, bash-debuginfo and / or bash-doc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bash-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(4|5\.6|5\.9|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.6 / 5.9 / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1311";
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
{  sp = get_kb_item("Host/RedHat/minor_release");
  if (isnull(sp)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");

  flag = 0;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"bash-3.0-27.el4.4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"bash-3.0-27.el4.4")) flag++;


  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"bash-3.2-24.el5_6.2")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"bash-3.2-32.el5_9.3")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"bash-3.2-32.el5_9.3")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"bash-3.2-24.el5_6.2")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"bash-3.2-32.el5_9.3")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"bash-debuginfo-3.2-24.el5_6.2")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"bash-debuginfo-3.2-32.el5_9.3")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"bash-debuginfo-3.2-32.el5_9.3")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"bash-debuginfo-3.2-24.el5_6.2")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"bash-debuginfo-3.2-32.el5_9.3")) flag++;


  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"bash-4.1.2-15.el6_4.2")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"bash-4.1.2-15.el6_4.2")) flag++;

if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"bash-4.1.2-9.el6_2.2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"bash-4.1.2-15.el6_4.2")) flag++; }

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"bash-debuginfo-4.1.2-15.el6_4.2")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"bash-debuginfo-4.1.2-15.el6_4.2")) flag++;

if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"bash-debuginfo-4.1.2-9.el6_2.2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"bash-debuginfo-4.1.2-15.el6_4.2")) flag++; }

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"bash-doc-4.1.2-15.el6_4.2")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"bash-doc-4.1.2-15.el6_4.2")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"bash-doc-4.1.2-15.el6_4.2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"bash-doc-4.1.2-9.el6_2.2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bash / bash-debuginfo / bash-doc");
  }
}
