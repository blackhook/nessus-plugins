#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0735 and 
# CentOS Errata and Security Advisory 2006:0735 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(36615);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-5462", "CVE-2006-5463", "CVE-2006-5464", "CVE-2006-5747", "CVE-2006-5748");
  script_bugtraq_id(19849);
  script_xref(name:"RHSA", value:"2006:0735");

  script_name(english:"CentOS 4 : thunderbird (CESA-2006:0735)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated thunderbird packages that fix several security bugs are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the way Thunderbird processes certain
malformed JavaScript code. A malicious HTML mail message could cause
the execution of JavaScript code in such a way that could cause
Thunderbird to crash or execute arbitrary code as the user running
Thunderbird. (CVE-2006-5463, CVE-2006-5747, CVE-2006-5748)

Several flaws were found in the way Thunderbird renders HTML mail
messages. A malicious HTML mail message could cause the mail client to
crash or possibly execute arbitrary code as the user running
Thunderbird. (CVE-2006-5464)

A flaw was found in the way Thunderbird verifies RSA signatures. For
RSA keys with exponent 3 it is possible for an attacker to forge a
signature that would be incorrectly verified by the NSS library.
Thunderbird as shipped trusts several root Certificate Authorities
that use exponent 3. An attacker could have created a carefully
crafted SSL certificate which would be incorrectly trusted when their
site was visited by a victim. This flaw was previously thought to be
fixed in Thunderbird 1.5.0.7, however Ulrich Kuehn discovered the fix
was incomplete (CVE-2006-5462)

Users of Thunderbird are advised to upgrade to this update, which
contains Thunderbird version 1.5.0.8 that corrects these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013383.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c63f31b4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013384.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c24cbeb4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/09");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"thunderbird-1.5.0.8-0.1.el4.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"thunderbird-1.5.0.8-0.1.el4.centos4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
