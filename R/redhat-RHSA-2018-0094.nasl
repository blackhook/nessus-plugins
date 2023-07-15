#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0094. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106089);
  script_version("3.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2017-5715");
  script_xref(name:"RHSA", value:"2018:0094");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"RHEL 7 : linux-firmware (RHSA-2018:0094) (Spectre)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for linux-firmware is now available for Red Hat Enterprise
Linux 7, Red Hat Enterprise Linux 7.2 Advanced Update Support, Red Hat
Enterprise Linux 7.2 Telco Extended Update Support, Red Hat Enterprise
Linux 7.2 Update Services for SAP Solutions, and Red Hat Enterprise
Linux 7.3 Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The linux-firmware packages contain all of the firmware files that are
required by various devices to operate.

This update supersedes microcode provided by Red Hat with the
CVE-2017-5715 ('Spectre') CPU branch injection vulnerability
mitigation. (Historically, Red Hat has provided updated microcode,
developed by our microprocessor partners, as a customer convenience.)
Further testing has uncovered problems with the microcode provided
along with the 'Spectre' mitigation that could lead to system
instabilities. As a result, Red Hat is providing an microcode update
that reverts to the last known good microcode version dated before 03
January 2018. Red Hat strongly recommends that customers contact their
hardware provider for the latest microcode updates.

IMPORTANT: Customers using Intel Skylake-, Broadwell-, and
Haswell-based platforms must obtain and install updated microcode from
their hardware vendor immediately. The 'Spectre' mitigation requires
both an updated kernel from Red Hat and updated microcode from your
hardware vendor."
  );
  # https://access.redhat.com/security/vulnerabilities/speculativeexecution
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?892ef523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:0094"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl100-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl1000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl105-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl135-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl2000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl2030-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl3160-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl3945-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl4965-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl5000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl5150-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl6000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl6000g2a-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl6000g2b-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl6050-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl7260-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl7265-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:linux-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:0094";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl100-firmware-39.31.5.1-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl100-firmware-39.31.5.1-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl100-firmware-39.31.5.1-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl1000-firmware-39.31.5.1-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl1000-firmware-39.31.5.1-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl1000-firmware-39.31.5.1-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl105-firmware-18.168.6.1-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl105-firmware-18.168.6.1-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl105-firmware-18.168.6.1-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl135-firmware-18.168.6.1-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl135-firmware-18.168.6.1-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl135-firmware-18.168.6.1-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl2000-firmware-18.168.6.1-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl2000-firmware-18.168.6.1-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl2000-firmware-18.168.6.1-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl2030-firmware-18.168.6.1-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl2030-firmware-18.168.6.1-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl2030-firmware-18.168.6.1-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl3160-firmware-22.0.7.0-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl3160-firmware-22.0.7.0-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl3160-firmware-22.0.7.0-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl3945-firmware-15.32.2.9-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl3945-firmware-15.32.2.9-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl3945-firmware-15.32.2.9-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl4965-firmware-228.61.2.24-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl4965-firmware-228.61.2.24-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl4965-firmware-228.61.2.24-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl5000-firmware-8.83.5.1_1-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl5000-firmware-8.83.5.1_1-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl5000-firmware-8.83.5.1_1-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl5150-firmware-8.24.2.2-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl5150-firmware-8.24.2.2-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl5150-firmware-8.24.2.2-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl6000-firmware-9.221.4.1-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl6000-firmware-9.221.4.1-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl6000-firmware-9.221.4.1-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl6000g2a-firmware-17.168.5.3-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl6000g2a-firmware-17.168.5.3-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl6000g2a-firmware-17.168.5.3-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl6000g2b-firmware-17.168.5.2-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl6000g2b-firmware-17.168.5.2-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl6000g2b-firmware-17.168.5.2-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl6050-firmware-41.28.5.1-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl6050-firmware-41.28.5.1-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl6050-firmware-41.28.5.1-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl7260-firmware-22.0.7.0-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl7260-firmware-22.0.7.0-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl7260-firmware-22.0.7.0-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"iwl7265-firmware-22.0.7.0-51.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"iwl7265-firmware-22.0.7.0-45.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"iwl7265-firmware-22.0.7.0-58.el7_4")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL7", sp:"3", reference:"linux-firmware-20160830-51.git7534e19.el7_3")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL7", sp:"2", reference:"linux-firmware-20150904-45.git6ebf5d5.el7_2")) flag++; }
  else { if (rpm_check(release:"RHEL7", reference:"linux-firmware-20170606-58.gitc990aae.el7_4")) flag++; }


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "iwl100-firmware / iwl1000-firmware / iwl105-firmware / etc");
  }
}
