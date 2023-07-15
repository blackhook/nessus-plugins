#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0722 and 
# CentOS Errata and Security Advisory 2007:0722 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25739);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-3089", "CVE-2007-3656", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738");
  script_bugtraq_id(24946);
  script_xref(name:"RHSA", value:"2007:0722");

  script_name(english:"CentOS 3 / 4 : seamonkey (CESA-2007:0722)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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

Several flaws were found in the way SeaMonkey processed certain
malformed JavaScript code. A web page containing malicious JavaScript
code could cause SeaMonkey to crash or potentially execute arbitrary
code as the user running SeaMonkey. (CVE-2007-3734, CVE-2007-3735,
CVE-2007-3737, CVE-2007-3738)

Several content injection flaws were found in the way SeaMonkey
handled certain JavaScript code. A web page containing malicious
JavaScript code could inject arbitrary content into other web pages.
(CVE-2007-3736, CVE-2007-3089)

A flaw was found in the way SeaMonkey cached web pages on the local
disk. A malicious web page may be able to inject arbitrary HTML into a
browsing session if the user reloads a targeted site. (CVE-2007-3656)

Users of SeaMonkey are advised to upgrade to these erratum packages,
which contain backported patches that correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014046.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83de6565"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014047.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?edbe854d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014050.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f9655a6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014051.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa57f7b5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014063.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78b77459"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014064.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97c75663"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"seamonkey-1.0.9-0.3.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-chat-1.0.9-0.3.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-devel-1.0.9-0.3.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-dom-inspector-1.0.9-0.3.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-js-debugger-1.0.9-0.3.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-mail-1.0.9-0.3.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nspr-1.0.9-0.3.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nspr-devel-1.0.9-0.3.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nss-1.0.9-0.3.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nss-devel-1.0.9-0.3.el3.centos3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"seamonkey-1.0.9-4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-chat-1.0.9-4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-devel-1.0.9-4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-dom-inspector-1.0.9-4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-js-debugger-1.0.9-4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-mail-1.0.9-4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-nspr-1.0.9-4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-nspr-devel-1.0.9-4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-nss-1.0.9-4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-nss-devel-1.0.9-4.el4.centos")) flag++;


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
