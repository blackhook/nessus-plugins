#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3532 and 
# CentOS Errata and Security Advisory 2018:3532 respectively.
#

include("compat.inc");

if (description)
{
  script_id(119051);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2018-12389", "CVE-2018-12390", "CVE-2018-12392", "CVE-2018-12393");
  script_xref(name:"RHSA", value:"2018:3532");

  script_name(english:"CentOS 7 : thunderbird (CESA-2018:3532)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for thunderbird is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 60.3.0.

Security Fix(es) :

* Mozilla: Memory safety bugs fixed in Firefox 63 and Firefox ESR 60.3
(CVE-2018-12390)

* Mozilla: Crash with nested event loops (CVE-2018-12392)

* Mozilla: Integer overflow during Unicode conversion while loading
JavaScript (CVE-2018-12393)

* Mozilla: Memory safety bugs fixed in Firefox ESR 60.3
(CVE-2018-12389)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Christian Holler, Bob Owen, Boris
Zbarsky, Calixte Denizet, Jason Kratzer, Jed Davis, Taegeon Lee,
Philipp, Ronald Crane, Raul Gurzau, Gary Kwong, Tyson Smith, Raymond
Forbes, Bogdan Tara, Nils, r, and Daniel Veditz as the original
reporters."
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-December/023128.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79975ff1"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005762.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a234a5f5"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12390");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"thunderbird-60.3.0-1.el7.centos", allowmaj:TRUE)) flag++;


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
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
