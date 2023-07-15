#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1877 and 
# CentOS Errata and Security Advisory 2018:1877 respectively.
#

include("compat.inc");

if (description)
{
  script_id(110647);
  script_version("1.5");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2017-12173");
  script_xref(name:"RHSA", value:"2018:1877");

  script_name(english:"CentOS 6 : ding-libs / sssd (CESA-2018:1877)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for sssd and ding-libs is now available for Red Hat
Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The System Security Services Daemon (SSSD) service provides a set of
daemons to manage access to remote directories and authentication
mechanisms. It also provides the Name Service Switch (NSS) and the
Pluggable Authentication Modules (PAM) interfaces toward the system,
and a pluggable back-end system to connect to multiple different
account sources.

The ding-libs packages contain a set of libraries used by the System
Security Services Daemon (SSSD) as well as other projects, and provide
functions to manipulate file system path names (libpath_utils), a hash
table to manage storage and access time properties (libdhash), a data
type to collect data in a hierarchical structure (libcollection), a
dynamically growing, reference-counted array (libref_array), and a
library to process configuration files in initialization format (INI)
into a library collection data structure (libini_config).

Security Fix(es) :

* sssd: unsanitized input when searching in local cache database
(CVE-2017-12173)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

This issue was discovered by Sumit Bose (Red Hat).

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.10 Release Notes and Red Hat Enterprise Linux 6.10
Technical Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-June/005245.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8c5b85e"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-June/005300.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d66b60ec"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ding-libs and / or sssd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12173");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libbasicobjects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libbasicobjects-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcollection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcollection-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libdhash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libdhash-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libini_config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libini_config-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpath_utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpath_utils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libref_array");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libref_array-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"libbasicobjects-0.1.1-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libbasicobjects-devel-0.1.1-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libcollection-0.6.2-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libcollection-devel-0.6.2-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libdhash-0.4.3-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libdhash-devel-0.4.3-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libini_config-1.1.0-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libini_config-devel-1.1.0-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libipa_hbac-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libipa_hbac-devel-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpath_utils-0.2.1-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpath_utils-devel-0.2.1-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libref_array-0.1.4-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libref_array-devel-0.1.4-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_idmap-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_idmap-devel-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_nss_idmap-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_nss_idmap-devel-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_simpleifp-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_simpleifp-devel-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-libipa_hbac-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-libsss_nss_idmap-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-sss-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-sss-murmur-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-sssdconfig-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-ad-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-client-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-common-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-common-pac-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-dbus-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-ipa-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-krb5-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-krb5-common-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-ldap-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-proxy-1.13.3-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-tools-1.13.3-60.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libbasicobjects / libbasicobjects-devel / libcollection / etc");
}
