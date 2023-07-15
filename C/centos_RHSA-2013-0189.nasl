#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0189 and 
# CentOS Errata and Security Advisory 2013:0189 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63673);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-5484");
  script_bugtraq_id(57529);
  script_xref(name:"RHSA", value:"2013:0189");

  script_name(english:"CentOS 5 : ipa-client (CESA-2013:0189)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated ipa-client package that fixes one security issue is now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Red Hat Identity Management is a centralized authentication, identity
management and authorization solution for both traditional and
cloud-based enterprise environments.

A weakness was found in the way IPA clients communicated with IPA
servers when initially attempting to join IPA domains. As there was no
secure way to provide the IPA server's Certificate Authority (CA)
certificate to the client during a join, the IPA client enrollment
process was susceptible to man-in-the-middle attacks. This flaw could
allow an attacker to obtain access to the IPA server using the
credentials provided by an IPA client, including administrative access
to the entire domain if the join was performed using an
administrator's credentials. (CVE-2012-5484)

Note: This weakness was only exposed during the initial client join to
the realm, because the IPA client did not yet have the CA certificate
of the server. Once an IPA client has joined the realm and has
obtained the CA certificate of the IPA server, all further
communication is secure. If a client were using the OTP (one-time
password) method to join to the realm, an attacker could only obtain
unprivileged access to the server (enough to only join the realm).

Red Hat would like to thank Petr Mensik for reporting this issue.

When a fix for this flaw has been applied to the client but not yet
the server, ipa-client-install, in unattended mode, will fail if you
do not have the correct CA certificate locally, noting that you must
use the '--force' option to insecurely obtain the certificate. In
interactive mode, the certificate will try to be obtained securely
from LDAP. If this fails, you will be prompted to insecurely download
the certificate via HTTP. In the same situation when using OTP, LDAP
will not be queried and you will be prompted to insecurely download
the certificate via HTTP.

Users of ipa-client are advised to upgrade to this updated package,
which corrects this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-January/019212.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ba35cfe"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ipa-client package."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5484");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"ipa-client-2.1.3-5.el5_9.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-client");
}
