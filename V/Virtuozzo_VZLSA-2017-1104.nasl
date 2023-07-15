#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101455);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2016-10195",
    "CVE-2016-10196",
    "CVE-2016-10197",
    "CVE-2017-5429",
    "CVE-2017-5432",
    "CVE-2017-5433",
    "CVE-2017-5434",
    "CVE-2017-5435",
    "CVE-2017-5436",
    "CVE-2017-5438",
    "CVE-2017-5439",
    "CVE-2017-5440",
    "CVE-2017-5441",
    "CVE-2017-5442",
    "CVE-2017-5443",
    "CVE-2017-5444",
    "CVE-2017-5445",
    "CVE-2017-5446",
    "CVE-2017-5447",
    "CVE-2017-5448",
    "CVE-2017-5449",
    "CVE-2017-5459",
    "CVE-2017-5460",
    "CVE-2017-5464",
    "CVE-2017-5465",
    "CVE-2017-5469"
  );

  script_name(english:"Virtuozzo 6 : firefox (VZLSA-2017-1104)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for firefox is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Mozilla Firefox is an open source web browser.

This update upgrades Firefox to version 52.1.0 ESR.

Security Fix(es) :

* Multiple flaws were found in the processing of malformed web
content. A web page containing malicious content could cause Firefox
to crash or, potentially, execute arbitrary code with the privileges
of the user running Firefox. (CVE-2017-5429, CVE-2017-5432,
CVE-2017-5433, CVE-2017-5434, CVE-2017-5435, CVE-2017-5436,
CVE-2017-5437, CVE-2017-5438, CVE-2017-5439, CVE-2017-5440,
CVE-2017-5441, CVE-2017-5442, CVE-2017-5443, CVE-2017-5444,
CVE-2017-5445, CVE-2017-5446, CVE-2017-5447, CVE-2017-5448,
CVE-2017-5449, CVE-2017-5459, CVE-2017-5460, CVE-2017-5464,
CVE-2017-5465, CVE-2017-5469)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Mozilla developers and community, Nils,
Holger Fuhrmannek, Atte Kettunen, Huzaifa Sidhpurwala, Nicolas
GrA(c)goire, Chamal De Silva, Chun Han Hsiao, Ivan Fratric of Google
Project Zero, Anonymous working with Trend Micro's Zero Day
Initiative, and Petr Cerny as the original reporters.

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-1104.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db3df90d");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-1104");
  script_set_attribute(attribute:"solution", value:
"Update the affected firefox package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 6.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["firefox-52.1.0-2.vl6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-6", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
