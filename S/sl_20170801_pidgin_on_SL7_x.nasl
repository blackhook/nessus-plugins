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
  script_id(102651);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3694", "CVE-2014-3695", "CVE-2014-3696", "CVE-2014-3698", "CVE-2017-2640");
  script_xref(name:"IAVB", value:"2017-B-0029");

  script_name(english:"Scientific Linux Security Update : pidgin on SL7.x x86_64 (20170801)");
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
"The following packages have been upgraded to a later upstream version:
pidgin (2.10.11).

Security Fix(es) :

  - A denial of service flaw was found in the way Pidgin's
    Mxit plug-in handled emoticons. A malicious remote
    server or a man-in-the-middle attacker could potentially
    use this flaw to crash Pidgin by sending a specially
    crafted emoticon. (CVE-2014-3695)

  - A denial of service flaw was found in the way Pidgin
    parsed Groupwise server messages. A malicious remote
    server or a man-in-the-middle attacker could potentially
    use this flaw to cause Pidgin to consume an excessive
    amount of memory, possibly leading to a crash, by
    sending a specially crafted message. (CVE-2014-3696)

  - An information disclosure flaw was discovered in the way
    Pidgin parsed XMPP messages. A malicious remote server
    or a man-in-the-middle attacker could potentially use
    this flaw to disclose a portion of memory belonging to
    the Pidgin process by sending a specially crafted XMPP
    message. (CVE-2014-3698)

  - An out-of-bounds write flaw was found in the way Pidgin
    processed XML content. A malicious remote server could
    potentially use this flaw to crash Pidgin or execute
    arbitrary code in the context of the pidgin process.
    (CVE-2017-2640)

  - It was found that Pidgin's SSL/TLS plug-ins had a flaw
    in the certificate validation functionality. An attacker
    could use this flaw to create a fake certificate, that
    Pidgin would trust, which could be used to conduct
    man-in-the-middle attacks against Pidgin.
    (CVE-2014-3694)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1708&L=scientific-linux-errata&F=&S=&P=16582
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae7715fc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pidgin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"finch-2.10.11-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"finch-devel-2.10.11-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libpurple-2.10.11-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libpurple-devel-2.10.11-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libpurple-perl-2.10.11-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libpurple-tcl-2.10.11-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pidgin-2.10.11-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pidgin-debuginfo-2.10.11-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pidgin-devel-2.10.11-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pidgin-perl-2.10.11-5.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / libpurple-perl / etc");
}
