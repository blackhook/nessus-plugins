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
  script_id(101387);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-8743");

  script_name(english:"Scientific Linux Security Update : httpd on SL6.x i386/x86_64 (20170711)");
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

  - It was discovered that the HTTP parser in httpd
    incorrectly allowed certain characters not permitted by
    the HTTP protocol specification to appear unencoded in
    HTTP request headers. If httpd was used in conjunction
    with a proxy or backend server that interpreted those
    characters differently, a remote attacker could possibly
    use this flaw to inject data into HTTP responses,
    resulting in proxy cache poisoning. (CVE-2016-8743)

Note: The fix for the CVE-2016-8743 issue causes httpd to return '400
Bad Request' error to HTTP clients which do not strictly follow HTTP
protocol specification. A newly introduced configuration directive
'HttpProtocolOptions Unsafe' can be used to re-enable the old less
strict parsing. However, such setting also re-introduces the
CVE-2016-8743 issue.

Note: Administrators of Red Hat Satellite 5 and Red Hat Satellite
Proxy 5 systems should consult Red Hat Knowledgebase article 3013361
linked to in the Reference section before installing this update.

Bug Fix(es) :

  - Previously, httpd was unable to correctly check a
    boundary of an array, and in rare cases it attempted to
    access an element of an array that was out of bounds.
    Consequently, httpd terminated unexpectedly with a
    segmentation fault at proxy_util.c. With this update,
    bounds checking has been fixed, and httpd no longer
    crashes."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1707&L=scientific-linux-errata&F=&S=&P=6813
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?120580a4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/12");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"httpd-2.2.15-60.el6_9.4")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-debuginfo-2.2.15-60.el6_9.4")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-devel-2.2.15-60.el6_9.4")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-manual-2.2.15-60.el6_9.4")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-tools-2.2.15-60.el6_9.4")) flag++;
if (rpm_check(release:"SL6", reference:"mod_ssl-2.2.15-60.el6_9.4")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
