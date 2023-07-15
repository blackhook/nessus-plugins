#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0480. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38769);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0791", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-1187", "CVE-2009-1188", "CVE-2009-3604", "CVE-2009-3606");
  script_bugtraq_id(34568, 34791);
  script_xref(name:"RHSA", value:"2009:0480");

  script_name(english:"RHEL 5 : poppler (RHSA-2009:0480)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated poppler packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Poppler is a Portable Document Format (PDF) rendering library, used by
applications such as Evince.

Multiple integer overflow flaws were found in poppler. An attacker
could create a malicious PDF file that would cause applications that
use poppler (such as Evince) to crash or, potentially, execute
arbitrary code when opened. (CVE-2009-0147, CVE-2009-1179,
CVE-2009-1187, CVE-2009-1188)

Multiple buffer overflow flaws were found in poppler's JBIG2 decoder.
An attacker could create a malicious PDF file that would cause
applications that use poppler (such as Evince) to crash or,
potentially, execute arbitrary code when opened. (CVE-2009-0146,
CVE-2009-1182)

Multiple flaws were found in poppler's JBIG2 decoder that could lead
to the freeing of arbitrary memory. An attacker could create a
malicious PDF file that would cause applications that use poppler
(such as Evince) to crash or, potentially, execute arbitrary code when
opened. (CVE-2009-0166, CVE-2009-1180)

Multiple input validation flaws were found in poppler's JBIG2 decoder.
An attacker could create a malicious PDF file that would cause
applications that use poppler (such as Evince) to crash or,
potentially, execute arbitrary code when opened. (CVE-2009-0800)

Multiple denial of service flaws were found in poppler's JBIG2
decoder. An attacker could create a malicious PDF file that would
cause applications that use poppler (such as Evince) to crash when
opened. (CVE-2009-0799, CVE-2009-1181, CVE-2009-1183)

Red Hat would like to thank Braden Thomas and Drew Yao of the Apple
Product Security team, and Will Dormann of the CERT/CC for responsibly
reporting these flaws.

Users are advised to upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-0146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-0147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-0166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-0195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-0791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-0799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-0800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-1179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-1180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-1181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-1182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-1183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-1187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-1188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-3604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-3606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2009:0480"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected poppler, poppler-devel and / or poppler-utils
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:0480";
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
  if (rpm_check(release:"RHEL5", reference:"poppler-0.5.4-4.4.el5_3.9")) flag++;

  if (rpm_check(release:"RHEL5", reference:"poppler-devel-0.5.4-4.4.el5_3.9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"poppler-utils-0.5.4-4.4.el5_3.9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"poppler-utils-0.5.4-4.4.el5_3.9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"poppler-utils-0.5.4-4.4.el5_3.9")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler / poppler-devel / poppler-utils");
  }
}
