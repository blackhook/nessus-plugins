#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0427 and 
# CentOS Errata and Security Advisory 2011:0427 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53431);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-1179");
  script_bugtraq_id(47269);
  script_xref(name:"RHSA", value:"2011:0427");

  script_name(english:"CentOS 5 : spice-xpi (CESA-2011:0427)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated spice-xpi package that fixes one security issue is now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The Simple Protocol for Independent Computing Environments (SPICE) is
a remote display protocol used in Red Hat Enterprise Linux for viewing
virtualized guests running on the Kernel-based Virtual Machine (KVM)
hypervisor, or on Red Hat Enterprise Virtualization Hypervisor.

The spice-xpi package provides a plug-in that allows the SPICE client
to run from within Mozilla Firefox.

An uninitialized pointer use flaw was found in the SPICE Firefox
plug-in. If a user were tricked into visiting a malicious web page
with Firefox while the SPICE plug-in was enabled, it could cause
Firefox to crash or, possibly, execute arbitrary code with the
privileges of the user running Firefox. (CVE-2011-1179)

Users of spice-xpi should upgrade to this updated package, which
contains a backported patch to correct this issue. After installing
the update, Firefox must be restarted for the changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017303.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?858521cc"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017304.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05cce38b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spice-xpi package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-xpi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"spice-xpi-2.2-2.3.el5_6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spice-xpi");
}
