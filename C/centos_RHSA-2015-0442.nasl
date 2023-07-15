#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0442 and 
# CentOS Errata and Security Advisory 2015:0442 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81897);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-5312", "CVE-2012-6662");
  script_xref(name:"RHSA", value:"2015:0442");

  script_name(english:"CentOS 7 : ipa (CESA-2015:0442)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ipa packages that fix two security issues, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Identity Management (IdM) is a centralized authentication,
identity management, and authorization solution for both traditional
and cloud-based enterprise environments.

Two cross-site scripting (XSS) flaws were found in jQuery, which
impacted the Identity Management web administrative interface, and
could allow an authenticated user to inject arbitrary HTML or web
script into the interface. (CVE-2010-5312, CVE-2012-6662)

Note: The IdM version provided by this update no longer uses jQuery.

This update adds several enhancements that are described in more
detail in the Red Hat Enterprise Linux 7.1 Release Notes, linked to in
the References section, including :

* Added the 'ipa-cacert-manage' command, which renews the
Certification Authority (CA) file. (BZ#886645)

* Added the ID Views feature. (BZ#891984)

* IdM now supports using one-time password (OTP) authentication and
allows gradual migration from proprietary OTP solutions to the IdM OTP
solution. (BZ#919228)

* Added the 'ipa-backup' and 'ipa-restore' commands to allow manual
backups. (BZ#951581)

* Added a solution for regulating access permissions to specific
sections of the IdM server. (BZ#976382)

This update also fixes several bugs, including :

* Previously, when IdM servers were configured to require the
Transport Layer Security protocol version 1.1 (TLSv1.1) or later in
the httpd server, the 'ipa' command-line utility failed. With this
update, running 'ipa' works as expected with TLSv1.1 or later.
(BZ#1156466)

In addition, this update adds multiple enhancements, including :

* The 'ipa-getkeytab' utility can now optionally fetch existing
keytabs from the KDC. Previously, retrieving an existing keytab was
not supported, as the only option was to generate a new key.
(BZ#1007367)

* You can now create and manage a '.' root zone on IdM servers. DNS
queries sent to the IdM DNS server use this configured zone instead of
the public zone. (BZ#1056202)

* The IdM server web UI has been updated and is now based on the
Patternfly framework, offering better responsiveness. (BZ#1108212)

* A new user attribute now enables provisioning systems to add custom
tags for user objects. The tags can be used for automember rules or
for additional local interpretation. (BZ#1108229)

* This update adds a new DNS zone type to ensure that forward and
master zones are better separated. As a result, the IdM DNS interface
complies with the forward zone semantics in BIND. (BZ#1114013)

* This update adds a set of Apache modules that external applications
can use to achieve tighter interaction with IdM beyond simple
authentication. (BZ# 1107555)

* IdM supports configuring automember rules for automated assignment
of users or hosts in respective groups according to their
characteristics, such as the 'userClass' or 'departmentNumber'
attributes. Previously, the rules could be applied only to new
entries. This update allows applying the rules also to existing users
or hosts. (BZ#1108226)

* The extdom plug-in translates Security Identifiers (SIDs) of Active
Directory (AD) users and groups to names and POSIX IDs. With this
update, extdom returns the full member list for groups and the full
list of group memberships for a user, the GECOS field, the home
directory, as well as the login shell of a user. Also, an optional
list of key-value pairs contains the SID of the requested object if
the SID is available. (BZ#1030699)

All ipa users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-March/001594.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6cfcd67b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ipa packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-5312");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-admintools-4.1.0-18.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-client-4.1.0-18.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-python-4.1.0-18.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-server-4.1.0-18.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.1.0-18.el7.centos")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-admintools / ipa-client / ipa-python / ipa-server / etc");
}
