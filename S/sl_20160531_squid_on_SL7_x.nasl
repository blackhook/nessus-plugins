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
  script_id(91513);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-0801", "CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4553", "CVE-2016-4554", "CVE-2016-4555", "CVE-2016-4556");

  script_name(english:"Scientific Linux Security Update : squid on SL7.x x86_64 (20160531)");
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

  - A buffer overflow flaw was found in the way the Squid
    cachemgr.cgi utility processed remotely relayed Squid
    input. When the CGI interface utility is used, a remote
    attacker could possibly use this flaw to execute
    arbitrary code. (CVE-2016-4051)

  - Buffer overflow and input validation flaws were found in
    the way Squid processed ESI responses. If Squid was used
    as a reverse proxy, or for TLS/HTTPS interception, a
    remote attacker able to control ESI components on an
    HTTP server could use these flaws to crash Squid,
    disclose parts of the stack memory, or possibly execute
    arbitrary code as the user running Squid.
    (CVE-2016-4052, CVE-2016-4053, CVE-2016-4054)

  - An input validation flaw was found in the way Squid
    handled intercepted HTTP Request messages. An attacker
    could use this flaw to bypass the protection against
    issues related to CVE-2009-0801, and perform cache
    poisoning attacks on Squid. (CVE-2016-4553)

  - An input validation flaw was found in Squid's
    mime_get_header_field() function, which is used to
    search for headers within HTTP requests. An attacker
    could send an HTTP request from the client side with
    specially crafted header Host header that bypasses
    same-origin security protections, causing Squid
    operating as interception or reverse-proxy to contact
    the wrong origin server. It could also be used for cache
    poisoning for client not following RFC 7230.
    (CVE-2016-4554)

  - A NULL pointer dereference flaw was found in the way
    Squid processes ESI responses. If Squid was used as a
    reverse proxy or for TLS/HTTPS interception, a malicious
    server could use this flaw to crash the Squid worker
    process. (CVE-2016-4555)

  - An incorrect reference counting flaw was found in the
    way Squid processes ESI responses. If Squid is
    configured as reverse-proxy, for TLS/HTTPS interception,
    an attacker controlling a server accessed by Squid,
    could crash the squid worker, causing a Denial of
    Service attack. (CVE-2016-4556)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1606&L=scientific-linux-errata&F=&S=&P=412
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d04bbdf6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected squid, squid-debuginfo and / or squid-sysvinit
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:squid-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:squid-sysvinit");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"squid-3.3.8-26.el7_2.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"squid-debuginfo-3.3.8-26.el7_2.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"squid-sysvinit-3.3.8-26.el7_2.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid / squid-debuginfo / squid-sysvinit");
}
