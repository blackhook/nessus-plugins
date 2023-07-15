#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1725 and 
# CentOS Errata and Security Advisory 2018:1725 respectively.
#

include("compat.inc");

if (description)
{
  script_id(110205);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2018-5150", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5159", "CVE-2018-5161", "CVE-2018-5162", "CVE-2018-5168", "CVE-2018-5170", "CVE-2018-5178", "CVE-2018-5183", "CVE-2018-5184", "CVE-2018-5185");
  script_xref(name:"RHSA", value:"2018:1725");

  script_name(english:"CentOS 7 : thunderbird (CESA-2018:1725)");
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

This update upgrades Thunderbird to version 52.8.0.

Security Fix(es) :

* Mozilla: Memory safety bugs fixed in Firefox 60 and Firefox ESR 52.8
(CVE-2018-5150)

* Mozilla: Backport critical security fixes in Skia (CVE-2018-5183)

* Mozilla: Use-after-free with SVG animations and clip paths
(CVE-2018-5154)

* Mozilla: Use-after-free with SVG animations and text paths
(CVE-2018-5155)

* Mozilla: Integer overflow and out-of-bounds write in Skia
(CVE-2018-5159)

* Mozilla: Full plaintext recovery in S/MIME via chosen-ciphertext
attack (CVE-2018-5184)

* Mozilla: Hang via malformed headers (CVE-2018-5161)

* Mozilla: Encrypted mail leaks plaintext through src attribute
(CVE-2018-5162)

* Mozilla: Lightweight themes can be installed without user
interaction (CVE-2018-5168)

* Mozilla: Filename spoofing for external attachments (CVE-2018-5170)

* Mozilla: Buffer overflow during UTF-8 to Unicode string conversion
through legacy extension (CVE-2018-5178)

* Mozilla: Leaking plaintext through HTML forms (CVE-2018-5185)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank the Mozilla project for reporting
CVE-2018-5150, CVE-2018-5154, CVE-2018-5155, CVE-2018-5159,
CVE-2018-5168, CVE-2018-5178, and CVE-2018-5183. Upstream acknowledges
Christoph Diehl, Randell Jesup, Tyson Smith, Alex Gaynor, Ronald
Crane, Julian Hector, Kannan Vijayan, Jason Kratzer, Mozilla
Developers, Nils, Ivan Fratric, Wladimir Palant, and Root Object as
the original reporters."
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-May/022848.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd94a0b1"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5150");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"thunderbird-52.8.0-1.el7.centos", allowmaj:TRUE)) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
