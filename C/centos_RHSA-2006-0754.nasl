#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0754 and 
# CentOS Errata and Security Advisory 2006:0754 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(23789);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-6169", "CVE-2006-6235");
  script_bugtraq_id(21306, 21462);
  script_xref(name:"RHSA", value:"2006:0754");

  script_name(english:"CentOS 3 / 4 : gnupg (CESA-2006:0754)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated GnuPG packages that fix two security issues are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

GnuPG is a utility for encrypting data and creating digital
signatures.

Tavis Ormandy discovered a stack overwrite flaw in the way GnuPG
decrypts messages. An attacker could create carefully crafted message
that could cause GnuPG to execute arbitrary code if a victim attempts
to decrypt the message. (CVE-2006-6235)

A heap based buffer overflow flaw was found in the way GnuPG
constructs messages to be written to the terminal during an
interactive session. An attacker could create a carefully crafted
message which with user interaction could cause GnuPG to execute
arbitrary code with the permissions of the user running GnuPG.
(CVE-2006-6169)

All users of GnuPG are advised to upgrade to this updated package,
which contains a backported patch to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-December/013418.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24f4faeb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-December/013419.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2af605cc"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-December/013420.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7e6a7f1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-December/013421.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d17a0faf"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-December/013429.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bed57bac"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-December/013430.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b0572ac"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gnupg package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnupg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"gnupg-1.2.1-19")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gnupg-1.2.6-8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnupg");
}
