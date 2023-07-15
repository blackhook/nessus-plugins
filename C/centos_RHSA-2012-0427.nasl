#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0427 and 
# CentOS Errata and Security Advisory 2012:0427 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58503);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-1569");
  script_bugtraq_id(52668);
  script_xref(name:"RHSA", value:"2012:0427");

  script_name(english:"CentOS 6 : libtasn1 (CESA-2012:0427)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libtasn1 packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

libtasn1 is a library developed for ASN.1 (Abstract Syntax Notation
One) structures management that includes DER (Distinguished Encoding
Rules) encoding and decoding.

A flaw was found in the way libtasn1 decoded DER data. An attacker
could create carefully-crafted DER encoded input (such as an X.509
certificate) that, when parsed by an application that uses libtasn1
(such as applications using GnuTLS), could cause the application to
crash. (CVE-2012-1569)

Red Hat would like to thank Matthew Hall of Mu Dynamics for reporting
this issue.

Users of libtasn1 are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. For the update
to take effect, all applications linked to the libtasn1 library must
be restarted, or the system rebooted."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-March/018531.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96979130"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtasn1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1569");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtasn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtasn1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtasn1-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"libtasn1-2.3-3.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libtasn1-devel-2.3-3.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libtasn1-tools-2.3-3.el6_2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtasn1 / libtasn1-devel / libtasn1-tools");
}