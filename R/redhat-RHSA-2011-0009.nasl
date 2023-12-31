#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0009. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51432);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-2640", "CVE-2010-2641", "CVE-2010-2642", "CVE-2010-2643");
  script_bugtraq_id(45678);
  script_xref(name:"RHSA", value:"2011:0009");

  script_name(english:"RHEL 6 : evince (RHSA-2011:0009)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated evince packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Evince is a document viewer.

An array index error was found in the DeVice Independent (DVI)
renderer's PK and VF font file parsers. A DVI file that references a
specially crafted font file could, when opened, cause Evince to crash
or, potentially, execute arbitrary code with the privileges of the
user running Evince. (CVE-2010-2640, CVE-2010-2641)

A heap-based buffer overflow flaw was found in the DVI renderer's AFM
font file parser. A DVI file that references a specially crafted font
file could, when opened, cause Evince to crash or, potentially,
execute arbitrary code with the privileges of the user running Evince.
(CVE-2010-2642)

An integer overflow flaw was found in the DVI renderer's TFM font file
parser. A DVI file that references a specially crafted font file
could, when opened, cause Evince to crash or, potentially, execute
arbitrary code with the privileges of the user running Evince.
(CVE-2010-2643)

Note: The above issues are not exploitable unless an attacker can
trick the user into installing a malicious font file.

Red Hat would like to thank the Evince development team for reporting
these issues. Upstream acknowledges Jon Larimer of IBM X-Force as the
original reporter of these issues.

Users are advised to upgrade to these updated packages, which contain
a backported patch to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2010-2640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2010-2641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2010-2642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2010-2643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2011:0009"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-dvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0009";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"evince-2.28.2-14.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"evince-2.28.2-14.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"evince-2.28.2-14.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"evince-debuginfo-2.28.2-14.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"evince-devel-2.28.2-14.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"evince-dvi-2.28.2-14.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"evince-dvi-2.28.2-14.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"evince-dvi-2.28.2-14.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"evince-libs-2.28.2-14.el6_0.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evince / evince-debuginfo / evince-devel / evince-dvi / evince-libs");
  }
}
