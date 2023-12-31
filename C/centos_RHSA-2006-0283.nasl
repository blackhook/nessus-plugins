#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0283 and 
# CentOS Errata and Security Advisory 2006:0283 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21992);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-0188", "CVE-2006-0195", "CVE-2006-0377");
  script_bugtraq_id(16756);
  script_xref(name:"RHSA", value:"2006:0283");

  script_name(english:"CentOS 3 / 4 : squirrelmail (CESA-2006:0283)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated squirrelmail package that fixes three security and many
other bug issues is now available. This update contains bug fixes of
upstream squirrelmail 1.4.6 with some additional improvements to
international language support.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

SquirrelMail is a standards-based webmail package written in PHP4.

A bug was found in the way SquirrelMail presents the right frame to
the user. If a user can be tricked into opening a carefully crafted
URL, it is possible to present the user with arbitrary HTML data.
(CVE-2006-0188)

A bug was found in the way SquirrelMail filters incoming HTML email.
It is possible to cause a victim's web browser to request remote
content by opening a HTML email while running a web browser that
processes certain types of invalid style sheets. Only Internet
Explorer is known to process such malformed style sheets.
(CVE-2006-0195)

A bug was found in the way SquirrelMail processes a request to select
an IMAP mailbox. If a user can be tricked into opening a carefully
crafted URL, it is possible to execute arbitrary IMAP commands as the
user viewing their mail with SquirrelMail. (CVE-2006-0377)

Users of SquirrelMail are advised to upgrade to this updated package,
which contains SquirrelMail version 1.4.6 and is not vulnerable to
these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012862.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7685c0a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012863.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f96dca0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012865.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d93d7699"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012867.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?731c0b4d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012877.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?630f1e62"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012878.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ffe6b73"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
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
if (rpm_check(release:"CentOS-3", reference:"squirrelmail-1.4.6-5.el3.centos.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"squirrelmail-1.4.6-5.el4.centos4")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squirrelmail");
}
