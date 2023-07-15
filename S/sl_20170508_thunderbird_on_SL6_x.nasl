#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100049);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-10195", "CVE-2016-10196", "CVE-2016-10197", "CVE-2017-5429", "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441", "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5449", "CVE-2017-5451", "CVE-2017-5454", "CVE-2017-5459", "CVE-2017-5460", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466", "CVE-2017-5467", "CVE-2017-5469");

  script_name(english:"Scientific Linux Security Update : thunderbird on SL6.x, SL7.x i386/x86_64 (20170508)");
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
"This update upgrades Thunderbird to version 52.1.0.

Security Fix(es) :

  - Multiple flaws were found in the processing of malformed
    web content. A web page containing malicious content
    could cause Thunderbird to crash or, potentially,
    execute arbitrary code with the privileges of the user
    running Thunderbird. (CVE-2017-5429, CVE-2017-5433,
    CVE-2017-5435, CVE-2017-5436, CVE-2017-5459,
    CVE-2017-5466, CVE-2017-5432, CVE-2017-5434,
    CVE-2017-5438, CVE-2017-5439, CVE-2017-5440,
    CVE-2017-5441, CVE-2017-5442, CVE-2017-5443,
    CVE-2017-5444, CVE-2017-5446, CVE-2017-5447,
    CVE-2017-5454, CVE-2017-5460, CVE-2017-5464,
    CVE-2017-5465, CVE-2017-5469, CVE-2016-10195,
    CVE-2016-10196, CVE-2017-5445, CVE-2017-5449,
    CVE-2017-5451, CVE-2017-5467, CVE-2016-10197)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1705&L=scientific-linux-errata&F=&S=&P=1683
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2d686b5"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"thunderbird-52.1.0-1.el6_9", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SL6", reference:"thunderbird-debuginfo-52.1.0-1.el6_9", allowmaj:TRUE)) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"thunderbird-52.1.0-1.el7_3", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"thunderbird-debuginfo-52.1.0-1.el7_3", allowmaj:TRUE)) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
}
