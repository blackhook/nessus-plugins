#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0970. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51133);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2010-4344");
  script_bugtraq_id(45308);
  script_xref(name:"RHSA", value:"2010:0970");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"RHEL 4 / 5 : exim (RHSA-2010:0970)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated exim packages that fix one security issue are now available
for Red Hat Enterprise Linux 4 and 5, and Red Hat Enterprise Linux
4.7, 5.3, and 5.4 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Exim is a mail transport agent (MTA) developed at the University of
Cambridge for use on Unix systems connected to the Internet.

A buffer overflow flaw was discovered in Exim's internal
string_vformat() function. A remote attacker could use this flaw to
execute arbitrary code on the mail server running Exim.
(CVE-2010-4344)

Note: successful exploitation would allow a remote attacker to execute
arbitrary code as root on a Red Hat Enterprise Linux 4 or 5 system
that is running the Exim mail server. An exploit for this issue is
known to exist.

For additional information regarding this flaw, along with mitigation
advice, please see the Knowledge Base article linked to in the
References section of this advisory.

Users of Exim are advised to update to these erratum packages which
contain a backported patch to correct this issue. After installing
this update, the Exim daemon will be restarted automatically.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-4344");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/43788");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2010:0970");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4344");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim4 string_format Function Heap Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:exim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:exim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:exim-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:exim-sa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0970";
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
if (sp == "7") {   if (rpm_check(release:"RHEL4", sp:"7", reference:"exim-4.43-1.RHEL4.5.el4_7.1")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"exim-4.43-1.RHEL4.5.el4_8.1")) flag++; }

if (sp == "7") {   if (rpm_check(release:"RHEL4", sp:"7", reference:"exim-doc-4.43-1.RHEL4.5.el4_7.1")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"exim-doc-4.43-1.RHEL4.5.el4_8.1")) flag++; }

if (sp == "7") {   if (rpm_check(release:"RHEL4", sp:"7", reference:"exim-mon-4.43-1.RHEL4.5.el4_7.1")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"exim-mon-4.43-1.RHEL4.5.el4_8.1")) flag++; }

if (sp == "7") {   if (rpm_check(release:"RHEL4", sp:"7", reference:"exim-sa-4.43-1.RHEL4.5.el4_7.1")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"exim-sa-4.43-1.RHEL4.5.el4_8.1")) flag++; }


if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"i386", reference:"exim-4.63-3.el5_4.1")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"exim-4.63-3.el5_3.1")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"exim-4.63-5.el5_5.2")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"exim-4.63-3.el5_4.1")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"exim-4.63-3.el5_3.1")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"exim-4.63-5.el5_5.2")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"exim-4.63-3.el5_4.1")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"exim-4.63-3.el5_3.1")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"exim-4.63-5.el5_5.2")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"i386", reference:"exim-mon-4.63-3.el5_4.1")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"exim-mon-4.63-3.el5_3.1")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"exim-mon-4.63-5.el5_5.2")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"exim-mon-4.63-3.el5_4.1")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"exim-mon-4.63-3.el5_3.1")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"exim-mon-4.63-5.el5_5.2")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"exim-mon-4.63-3.el5_4.1")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"exim-mon-4.63-3.el5_3.1")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"exim-mon-4.63-5.el5_5.2")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"i386", reference:"exim-sa-4.63-3.el5_4.1")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"exim-sa-4.63-3.el5_3.1")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"exim-sa-4.63-5.el5_5.2")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"exim-sa-4.63-3.el5_4.1")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"exim-sa-4.63-3.el5_3.1")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"exim-sa-4.63-5.el5_5.2")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"exim-sa-4.63-3.el5_4.1")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"exim-sa-4.63-3.el5_3.1")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"exim-sa-4.63-5.el5_5.2")) flag++; }


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exim / exim-doc / exim-mon / exim-sa");
  }
}
