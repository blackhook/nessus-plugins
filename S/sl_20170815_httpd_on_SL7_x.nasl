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
  script_id(102668);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7668", "CVE-2017-7679", "CVE-2017-9788");

  script_name(english:"Scientific Linux Security Update : httpd on SL7.x x86_64 (20170815)");
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
"Security Fix(es) :

  - It was discovered that the httpd's mod_auth_digest
    module did not properly initialize memory before using
    it when processing certain headers related to digest
    authentication. A remote attacker could possibly use
    this flaw to disclose potentially sensitive information
    or cause httpd child process to crash by sending
    specially crafted requests to a server. (CVE-2017-9788)

  - It was discovered that the use of httpd's
    ap_get_basic_auth_pw() API function outside of the
    authentication phase could lead to authentication
    bypass. A remote attacker could possibly use this flaw
    to bypass required authentication if the API was used
    incorrectly by one of the modules used by httpd.
    (CVE-2017-3167)

  - A NULL pointer dereference flaw was found in the httpd's
    mod_ssl module. A remote attacker could use this flaw to
    cause an httpd child process to crash if another module
    used by httpd called a certain API function during the
    processing of an HTTPS request. (CVE-2017-3169)

  - A buffer over-read flaw was found in the httpd's
    ap_find_token() function. A remote attacker could use
    this flaw to cause httpd child process to crash via a
    specially crafted HTTP request. (CVE-2017-7668)

  - A buffer over-read flaw was found in the httpd's
    mod_mime module. A user permitted to modify httpd's MIME
    configuration could use this flaw to cause httpd child
    process to crash. (CVE-2017-7679)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1708&L=scientific-linux-errata&F=&S=&P=5015
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b532292f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/22");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"httpd-2.4.6-67.el7_4.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"httpd-debuginfo-2.4.6-67.el7_4.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"httpd-devel-2.4.6-67.el7_4.2")) flag++;
if (rpm_check(release:"SL7", reference:"httpd-manual-2.4.6-67.el7_4.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"httpd-tools-2.4.6-67.el7_4.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mod_ldap-2.4.6-67.el7_4.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mod_proxy_html-2.4.6-67.el7_4.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mod_session-2.4.6-67.el7_4.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mod_ssl-2.4.6-67.el7_4.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-debuginfo / httpd-devel / httpd-manual / httpd-tools / etc");
}
