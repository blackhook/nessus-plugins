#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1059 and 
# CentOS Errata and Security Advisory 2009:1059 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38868);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-2927", "CVE-2009-1373", "CVE-2009-1376");
  script_bugtraq_id(35067);
  script_xref(name:"RHSA", value:"2009:1059");

  script_name(english:"CentOS 3 : pidgin (CESA-2009:1059)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated pidgin package that fixes two security issues is now
available for Red Hat Enterprise Linux 3.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

A buffer overflow flaw was found in the way Pidgin initiates file
transfers when using the Extensible Messaging and Presence Protocol
(XMPP). If a Pidgin client initiates a file transfer, and the remote
target sends a malformed response, it could cause Pidgin to crash or,
potentially, execute arbitrary code with the permissions of the user
running Pidgin. This flaw only affects accounts using XMPP, such as
Jabber and Google Talk. (CVE-2009-1373)

It was discovered that on 32-bit platforms, the Red Hat Security
Advisory RHSA-2008:0584 provided an incomplete fix for the integer
overflow flaw affecting Pidgin's MSN protocol handler. If a Pidgin
client receives a specially crafted MSN message, it may be possible to
execute arbitrary code with the permissions of the user running
Pidgin. (CVE-2009-1376)

Note: By default, when using an MSN account, only users on your buddy
list can send you messages. This prevents arbitrary MSN users from
exploiting this flaw.

All Pidgin users should upgrade to this update package, which contains
backported patches to resolve these issues. Pidgin must be restarted
for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015889.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?499986f1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015890.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4360e24d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015933.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?550bbf06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/23");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"pidgin-1.5.1-3.el3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pidgin");
}
