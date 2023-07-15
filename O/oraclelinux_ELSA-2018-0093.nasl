#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:0093 and 
# Oracle Linux Security Advisory ELSA-2018-0093 respectively.
#

include("compat.inc");

if (description)
{
  script_id(106118);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2017-5715");
  script_xref(name:"RHSA", value:"2018:0093");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"Oracle Linux 6 / 7 : microcode_ctl (ELSA-2018-0093) (Spectre)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"From Red Hat Security Advisory 2018:0093 :

An update for microcode_ctl is now available for Red Hat Enterprise
Linux 6, Red Hat Enterprise Linux 6.2 Advanced Update Support, Red Hat
Enterprise Linux 6.4 Advanced Update Support, Red Hat Enterprise Linux
6.5 Advanced Update Support, Red Hat Enterprise Linux 6.6 Advanced
Update Support, Red Hat Enterprise Linux 6.6 Telco Extended Update
Support, Red Hat Enterprise Linux 6.7 Extended Update Support, Red Hat
Enterprise Linux 7, Red Hat Enterprise Linux 7.2 Advanced Update
Support, Red Hat Enterprise Linux 7.2 Telco Extended Update Support,
Red Hat Enterprise Linux 7.2 Update Services for SAP Solutions, and
Red Hat Enterprise Linux 7.3 Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The microcode_ctl packages provide microcode updates for Intel and AMD
processors.

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
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-January/007461.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-January/007462.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected microcode_ctl package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:microcode_ctl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"microcode_ctl-1.17-25.4.0.1.el6_9")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"microcode_ctl-2.1-22.5.0.2.el7_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "microcode_ctl");
}
