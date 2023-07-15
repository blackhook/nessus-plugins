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
  script_id(99350);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-0736", "CVE-2016-2161", "CVE-2016-8743");

  script_name(english:"Scientific Linux Security Update : httpd on SL7.x x86_64 (20170412)");
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

  - It was discovered that the mod_session_crypto module of
    httpd did not use any mechanisms to verify integrity of
    the encrypted session data stored in the user's browser.
    A remote attacker could use this flaw to decrypt and
    modify session data using a padding oracle attack.
    (CVE-2016-0736)

  - It was discovered that the mod_auth_digest module of
    httpd did not properly check for memory allocation
    failures. A remote attacker could use this flaw to cause
    httpd child processes to repeatedly crash if the server
    used HTTP digest authentication. (CVE-2016-2161)

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

Bug Fix(es) :

  - When waking up child processes during a graceful
    restart, the httpd parent process could attempt to open
    more connections than necessary if a large number of
    child processes had been active prior to the restart.
    Consequently, a graceful restart could take a long time
    to complete. With this update, httpd has been fixed to
    limit the number of connections opened during a graceful
    restart to the number of active children, and the
    described problem no longer occurs.

  - Previously, httpd running in a container returned the
    500 HTTP status code (Internal Server Error) when a
    connection to a WebSocket server was closed. As a
    consequence, the httpd server failed to deliver the
    correct HTTP status and data to a client. With this
    update, httpd correctly handles all proxied requests to
    the WebSocket server, and the described problem no
    longer occurs.

  - In a configuration using LDAP authentication with the
    mod_authnz_ldap module, the name set using the
    AuthLDAPBindDN directive was not correctly used to bind
    to the LDAP server for all queries. Consequently,
    authorization attempts failed. The LDAP modules have
    been fixed to ensure the configured name is correctly
    bound for LDAP queries, and authorization using LDAP no
    longer fails."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1704&L=scientific-linux-errata&F=&S=&P=7439
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de4aeca1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/13");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"httpd-2.4.6-45.el7_3.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"httpd-debuginfo-2.4.6-45.el7_3.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"httpd-devel-2.4.6-45.el7_3.4")) flag++;
if (rpm_check(release:"SL7", reference:"httpd-manual-2.4.6-45.el7_3.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"httpd-tools-2.4.6-45.el7_3.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mod_ldap-2.4.6-45.el7_3.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mod_proxy_html-2.4.6-45.el7_3.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mod_session-2.4.6-45.el7_3.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mod_ssl-2.4.6-45.el7_3.4")) flag++;


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
