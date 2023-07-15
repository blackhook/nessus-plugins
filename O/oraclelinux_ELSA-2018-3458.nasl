#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:3458 and 
# Oracle Linux Security Advisory ELSA-2018-3458 respectively.
#

include("compat.inc");

if (description)
{
  script_id(118813);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2017-16541", "CVE-2018-12376", "CVE-2018-12377", "CVE-2018-12378", "CVE-2018-12379", "CVE-2018-12383", "CVE-2018-12385");
  script_xref(name:"RHSA", value:"2018:3458");

  script_name(english:"Oracle Linux 7 : thunderbird (ELSA-2018-3458)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"From Red Hat Security Advisory 2018:3458 :

An update for thunderbird is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 60.2.1.

Security Fix(es) :

* Mozilla: Memory safety bugs fixed in Firefox 62 and Firefox ESR 60.2
(CVE-2018-12376)

* Mozilla: Use-after-free in driver timers (CVE-2018-12377)

* Mozilla: Use-after-free in IndexedDB (CVE-2018-12378)

* Mozilla: Proxy bypass using automount and autofs (CVE-2017-16541)

* Mozilla: Out-of-bounds write with malicious MAR file
(CVE-2018-12379)

* Mozilla: Crash in TransportSecurityInfo due to cached data
(CVE-2018-12385)

* Mozilla: Setting a master password post-Firefox 58 does not delete
unencrypted previously stored passwords (CVE-2018-12383)

Note: All of the above issues cannot be exploited in Thunderbird by a
specially crafted HTML mail, as JavaScript is disabled for mail
messages and cannot be enabled. They could be exploited another way in
Thunderbird, for example, when viewing the remote content of an RSS
feed.

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Alex Gaynor, Boris Zbarsky, Christoph
Diehl, Christian Holler, Jason Kratzer, Jed Davis, Tyson Smith, Bogdan
Tara, Karl Tomlinson, Mats Palmgren, Nika Layzell, Ted Campbell, Nils,
Zhanjia Song, Holger Fuhrmannek, Philipp, and Jurgen Gaeremyn as the
original reporters."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-November/008222.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"thunderbird-60.2.1-4.0.1.el7_5", allowmaj:TRUE)) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
