#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0224. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78999);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-5783");
  script_bugtraq_id(58073);
  script_xref(name:"RHSA", value:"2014:0224");

  script_name(english:"RHEL 6 : redhat-support-plugin-rhev (RHSA-2014:0224)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated redhat-support-plugin-rhev package that fixes one security
issue is now available.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The Red Hat Support plug-in for Red Hat Enterprise Virtualization is a
new feature which offers seamless integrated access to Red Hat Access
services from the Red Hat Enterprise Virtualization Administration
Portal. The plug-in provides automated functionality that enables
quicker help, answers, and proactive services. It offers easy and
instant access to Red Hat exclusive knowledge, resources, engagement,
and diagnostic features.

Detailed information about this plug-in can be found in the Red Hat
Customer Portal at https://access.redhat.com/site/articles/425603

The Jakarta Commons HttpClient component did not verify that the
server hostname matched the domain name in the subject's Common Name
(CN) or subjectAltName field in X.509 certificates. This could allow a
man-in-the-middle attacker to spoof an SSL server if they had a
certificate that was valid for any domain name. (CVE-2012-5783)

All users of the Red Hat Support plug-in on Red Hat Enterprise
Virtualization Manager are advised to install this updated package,
which fixes this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/site/articles/425603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0224.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5783.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected redhat-support-plugin-rhev package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-support-plugin-rhev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_exists(rpm:"redhat-support-plugin-rhev-3\.3\.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"redhat-support-plugin-rhev-3.3.0-14.el6ev")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "redhat-support-plugin-rhev-3.3");
}
