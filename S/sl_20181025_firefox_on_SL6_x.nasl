#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(118442);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/02");

  script_cve_id("CVE-2018-12389", "CVE-2018-12390", "CVE-2018-12392", "CVE-2018-12393", "CVE-2018-12395", "CVE-2018-12396", "CVE-2018-12397");

  script_name(english:"Scientific Linux Security Update : firefox on SL6.x i386/x86_64 (20181025)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update upgrades Firefox to version 60.3.0 ESR.

Security Fix(es) :

  - Mozilla: Memory safety bugs fixed in Firefox 63 and
    Firefox ESR 60.3 (CVE-2018-12390)

  - Mozilla: Crash with nested event loops (CVE-2018-12392)

  - Mozilla: Integer overflow during Unicode conversion
    while loading JavaScript (CVE-2018-12393)

  - Mozilla: WebExtension bypass of domain restrictions
    through header rewriting (CVE-2018-12395)

  - Mozilla: WebExtension content scripts can execute in
    disallowed contexts (CVE-2018-12396)

  - Mozilla: WebExtension local file permission check bypass
    (CVE-2018-12397)

  - Mozilla: Memory safety bugs fixed in Firefox ESR 60.3
    (CVE-2018-12389)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1810&L=scientific-linux-errata&F=&S=&P=12900
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a63b23d4"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected firefox and / or firefox-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12392");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"firefox-60.3.0-1.el6", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SL6", reference:"firefox-debuginfo-60.3.0-1.el6", allowmaj:TRUE)) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-debuginfo");
}
