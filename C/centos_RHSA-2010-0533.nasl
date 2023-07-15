#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0533 and 
# CentOS Errata and Security Advisory 2010:0533 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47740);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-4901", "CVE-2010-0407");
  script_bugtraq_id(40758);
  script_xref(name:"RHSA", value:"2010:0533");

  script_name(english:"CentOS 5 : pcsc-lite (CESA-2010:0533)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pcsc-lite packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PC/SC Lite provides a Windows SCard compatible interface for
communicating with smart cards, smart card readers, and other security
tokens.

Multiple buffer overflow flaws were discovered in the way the pcscd
daemon, a resource manager that coordinates communications with smart
card readers and smart cards connected to the system, handled client
requests. A local user could create a specially crafted request that
would cause the pcscd daemon to crash or, possibly, execute arbitrary
code. (CVE-2010-0407, CVE-2009-4901)

Users of pcsc-lite should upgrade to these updated packages, which
contain a backported patch to correct these issues. After installing
this update, the pcscd daemon will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-July/016783.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f26fea84"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-July/016784.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?406ad116"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pcsc-lite packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcsc-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcsc-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcsc-lite-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcsc-lite-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"pcsc-lite-1.4.4-4.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pcsc-lite-devel-1.4.4-4.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pcsc-lite-doc-1.4.4-4.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pcsc-lite-libs-1.4.4-4.el5_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcsc-lite / pcsc-lite-devel / pcsc-lite-doc / pcsc-lite-libs");
}
