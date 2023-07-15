#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0977 and 
# CentOS Errata and Security Advisory 2008:0977 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(36485);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-0017", "CVE-2008-5012", "CVE-2008-5013", "CVE-2008-5014", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5019", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023", "CVE-2008-5024");
  script_bugtraq_id(32281);
  script_xref(name:"RHSA", value:"2008:0977");

  script_name(english:"CentOS 3 / 4 : seamonkey (CESA-2008:0977)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated SeaMonkey packages that fix security issues are now available
for Red Hat Enterprise Linux 2.1, Red Hat Enterprise Linux 3 and Red
Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

SeaMonkey is an open source Web browser, email and newsgroup client,
IRC chat client, and HTML editor.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause SeaMonkey to crash
or, potentially, execute arbitrary code as the user running SeaMonkey.
(CVE-2008-0017, CVE-2008-5013, CVE-2008-5014, CVE-2008-5016,
CVE-2008-5017, CVE-2008-5018, CVE-2008-5019, CVE-2008-5021)

Several flaws were found in the way malformed content was processed. A
web site containing specially crafted content could potentially trick
a SeaMonkey user into surrendering sensitive information.
(CVE-2008-5012, CVE-2008-5022, CVE-2008-5023, CVE-2008-5024)

All SeaMonkey users should upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015402.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c7a22ed"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015403.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de662a39"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015408.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1c10c0b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015422.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ca8f2aa"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015423.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?afc9856f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015447.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48254443"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79, 94, 119, 189, 200, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-1.0.9-0.25.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-chat-1.0.9-0.25.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-devel-1.0.9-0.25.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-dom-inspector-1.0.9-0.25.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-js-debugger-1.0.9-0.25.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-mail-1.0.9-0.25.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nspr-1.0.9-0.25.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nspr-devel-1.0.9-0.25.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nss-1.0.9-0.25.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nss-devel-1.0.9-0.25.el3.centos3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"seamonkey-1.0.9-28.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-chat-1.0.9-28.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-devel-1.0.9-28.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-dom-inspector-1.0.9-28.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-js-debugger-1.0.9-28.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-mail-1.0.9-28.el4.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey / seamonkey-chat / seamonkey-devel / etc");
}
