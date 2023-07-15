#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:3005 and 
# Oracle Linux Security Advisory ELSA-2018-3005 respectively.
#

include('compat.inc');

if (description)
{
  script_id(118368);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/03");

  script_cve_id(
    "CVE-2018-12389",
    "CVE-2018-12390",
    "CVE-2018-12392",
    "CVE-2018-12393",
    "CVE-2018-12395",
    "CVE-2018-12396",
    "CVE-2018-12397"
  );
  script_xref(name:"RHSA", value:"2018:3005");

  script_name(english:"Oracle Linux 7 : firefox (ELSA-2018-3005)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"From Red Hat Security Advisory 2018:3005 :

An update for firefox is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Mozilla Firefox is an open source web browser, designed for standards
compliance, performance, and portability.

This update upgrades Firefox to version 60.3.0 ESR.

Security Fix(es) :

* Mozilla: Memory safety bugs fixed in Firefox 63 and Firefox ESR 60.3
(CVE-2018-12390)

* Mozilla: Crash with nested event loops (CVE-2018-12392)

* Mozilla: Integer overflow during Unicode conversion while loading
JavaScript (CVE-2018-12393)

* Mozilla: WebExtension bypass of domain restrictions through header
rewriting (CVE-2018-12395)

* Mozilla: WebExtension content scripts can execute in disallowed
contexts (CVE-2018-12396)

* Mozilla: WebExtension local file permission check bypass
(CVE-2018-12397)

* Mozilla: Memory safety bugs fixed in Firefox ESR 60.3
(CVE-2018-12389)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Christian Holler, Bob Owen, Boris
Zbarsky, Calixte Denizet, Jason Kratzer, Jed Davis, Taegeon Lee,
Philipp, Ronald Crane, Raul Gurzau, Gary Kwong, Tyson Smith, Raymond
Forbes, Bogdan Tara, Nils, r, Rob Wu, Andrew Swan, and Daniel Veditz
as the original reporters.

Bug Fix(es) :

* Previously, passwords saved in the Firefox browser and encrypted by
a master password were erased when Firefox was exited. This update
ensures that NSS files used to decrypt stored login data are handled
correctly. As a result, the affected passwords are no longer lost
after restarting Firefox. (BZ#1638082)");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2018-October/008167.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected firefox package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12392");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"firefox-60.3.0-1.0.1.el7_5", allowmaj:TRUE)) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
