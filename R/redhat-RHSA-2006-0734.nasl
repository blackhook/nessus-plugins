#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0734. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(23681);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-5462", "CVE-2006-5463", "CVE-2006-5464", "CVE-2006-5747", "CVE-2006-5748");
  script_bugtraq_id(19849);
  script_xref(name:"RHSA", value:"2006:0734");

  script_name(english:"RHEL 2.1 / 3 / 4 : seamonkey (RHSA-2006:0734)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated SeaMonkey packages that fix several security bugs are now
available for Red Hat Enterprise Linux 2.1, 3, and 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

SeaMonkey is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

Several flaws were found in the way SeaMonkey processes certain
malformed JavaScript code. A malicious web page could cause the
execution of JavaScript code in such a way that could cause SeaMonkey
to crash or execute arbitrary code as the user running SeaMonkey.
(CVE-2006-5463, CVE-2006-5747, CVE-2006-5748)

Several flaws were found in the way SeaMonkey renders web pages. A
malicious web page could cause the browser to crash or possibly
execute arbitrary code as the user running SeaMonkey. (CVE-2006-5464)

A flaw was found in the way SeaMonkey verifies RSA signatures. For RSA
keys with exponent 3 it is possible for an attacker to forge a
signature that would be incorrectly verified by the NSS library.
SeaMonkey as shipped trusts several root Certificate Authorities that
use exponent 3. An attacker could have created a carefully crafted SSL
certificate which be incorrectly trusted when their site was visited
by a victim. This flaw was previously thought to be fixed in SeaMonkey
1.0.5, however Ulrich Kuehn discovered the fix was incomplete
(CVE-2006-5462)

Users of SeaMonkey are advised to upgrade to these erratum packages,
which contains SeaMonkey version 1.0.6 that corrects these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2006:0734"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(2\.1|3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2006:0734";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-1.0.6-0.1.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-chat-1.0.6-0.1.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-devel-1.0.6-0.1.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-dom-inspector-1.0.6-0.1.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-js-debugger-1.0.6-0.1.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-mail-1.0.6-0.1.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-nspr-1.0.6-0.1.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-nspr-devel-1.0.6-0.1.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-nss-1.0.6-0.1.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-nss-devel-1.0.6-0.1.el2")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-1.0.6-0.1.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-chat-1.0.6-0.1.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-devel-1.0.6-0.1.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-dom-inspector-1.0.6-0.1.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-js-debugger-1.0.6-0.1.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-mail-1.0.6-0.1.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-nspr-1.0.6-0.1.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-nspr-devel-1.0.6-0.1.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-nss-1.0.6-0.1.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-nss-devel-1.0.6-0.1.el3")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"devhelp-0.10-0.5.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"devhelp-0.10-0.5.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"devhelp-devel-0.10-0.5.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"devhelp-devel-0.10-0.5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-1.0.6-0.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-chat-1.0.6-0.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-devel-1.0.6-0.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-dom-inspector-1.0.6-0.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-js-debugger-1.0.6-0.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-mail-1.0.6-0.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-nspr-1.0.6-0.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-nspr-devel-1.0.6-0.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-nss-1.0.6-0.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-nss-devel-1.0.6-0.1.el4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-devel / seamonkey / seamonkey-chat / etc");
  }
}
