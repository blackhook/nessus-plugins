#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1254 and 
# CentOS Errata and Security Advisory 2015:1254 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85009);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-3613", "CVE-2014-3707", "CVE-2014-8150", "CVE-2015-3143", "CVE-2015-3148");
  script_bugtraq_id(69748, 70988, 71964, 74299, 74301);
  script_xref(name:"RHSA", value:"2015:1254");

  script_name(english:"CentOS 6 : curl (CESA-2015:1254)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated curl packages that fix multiple security issues, several bugs,
and add two enhancements are now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The curl packages provide the libcurl library and the curl utility for
downloading files from servers using various protocols, including
HTTP, FTP, and LDAP.

It was found that the libcurl library did not correctly handle partial
literal IP addresses when parsing received HTTP cookies. An attacker
able to trick a user into connecting to a malicious server could use
this flaw to set the user's cookie to a crafted domain, making other
cookie-related issues easier to exploit. (CVE-2014-3613)

A flaw was found in the way the libcurl library performed the
duplication of connection handles. If an application set the
CURLOPT_COPYPOSTFIELDS option for a handle, using the handle's
duplicate could cause the application to crash or disclose a portion
of its memory. (CVE-2014-3707)

It was discovered that the libcurl library failed to properly handle
URLs with embedded end-of-line characters. An attacker able to make an
application using libcurl to access a specially crafted URL via an
HTTP proxy could use this flaw to inject additional headers to the
request or construct additional requests. (CVE-2014-8150)

It was discovered that libcurl implemented aspects of the NTLM and
Negotiate authentication incorrectly. If an application uses libcurl
and the affected mechanisms in a specific way, certain requests to a
previously NTLM-authenticated server could appears as sent by the
wrong authenticated user. Additionally, the initial set of credentials
for HTTP Negotiate-authenticated requests could be reused in
subsequent requests, although a different set of credentials was
specified. (CVE-2015-3143, CVE-2015-3148)

Red Hat would like to thank the cURL project for reporting these
issues.

Bug fixes :

* An out-of-protocol fallback to SSL version 3.0 (SSLv3.0) was
available with libcurl. Attackers could abuse the fallback to force
downgrade of the SSL version. The fallback has been removed from
libcurl. Users requiring this functionality can explicitly enable
SSLv3.0 through the libcurl API. (BZ#1154059)

* A single upload transfer through the FILE protocol opened the
destination file twice. If the inotify kernel subsystem monitored the
file, two events were produced unnecessarily. The file is now opened
only once per upload. (BZ#883002)

* Utilities using libcurl for SCP/SFTP transfers could terminate
unexpectedly when the system was running in FIPS mode. (BZ#1008178)

* Using the '--retry' option with the curl utility could cause curl to
terminate unexpectedly with a segmentation fault. Now, adding
'--retry' no longer causes curl to crash. (BZ#1009455)

* The 'curl --trace-time' command did not use the correct local time
when printing timestamps. Now, 'curl --trace-time' works as expected.
(BZ#1120196)

* The valgrind utility could report dynamically allocated memory leaks
on curl exit. Now, curl performs a global shutdown of the NetScape
Portable Runtime (NSPR) library on exit, and valgrind no longer
reports the memory leaks. (BZ#1146528)

* Previously, libcurl returned an incorrect value of the
CURLINFO_HEADER_SIZE field when a proxy server appended its own
headers to the HTTP response. Now, the returned value is valid.
(BZ#1161163)

Enhancements :

* The '--tlsv1.0', '--tlsv1.1', and '--tlsv1.2' options are available
for specifying the minor version of the TLS protocol to be negotiated
by NSS. The '--tlsv1' option now negotiates the highest version of the
TLS protocol supported by both the client and the server. (BZ#1012136)

* It is now possible to explicitly enable or disable the ECC and the
new AES cipher suites to be used for TLS. (BZ#1058767, BZ#1156422)

All curl users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-July/002018.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c96865b1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3613");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"curl-7.19.7-46.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libcurl-7.19.7-46.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libcurl-devel-7.19.7-46.el6")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / libcurl / libcurl-devel");
}
