#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0505 and 
# CentOS Errata and Security Advisory 2013:0505 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65140);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-5643");
  script_bugtraq_id(56957);
  script_xref(name:"RHSA", value:"2013:0505");

  script_name(english:"CentOS 6 : squid (CESA-2013:0505)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated squid packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Squid is a high-performance proxy caching server for web clients that
supports FTP, Gopher, and HTTP data objects.

A denial of service flaw was found in the way the Squid Cache Manager
processed certain requests. A remote attacker who is able to access
the Cache Manager CGI could use this flaw to cause Squid to consume an
excessive amount of memory. (CVE-2012-5643)

This update also fixes the following bugs :

* Due to a bug in the ConnStateData::noteMoreBodySpaceAvailable()
function, child processes of Squid terminated upon encountering a
failed assertion. An upstream patch has been provided and Squid child
processes no longer terminate. (BZ#805879)

* Due to an upstream patch, which renamed the HTTP header controlling
persistent connections from 'Proxy-Connection' to 'Connection', the
NTLM pass-through authentication does not work, thus preventing login.
This update adds the new 'http10' option to the squid.conf file, which
can be used to enable the change in the patch. This option is set to
'off' by default. When set to 'on', the NTLM pass-through
authentication works properly, thus allowing login attempts to
succeed. (BZ#844723)

* When the IPv6 protocol was disabled and Squid tried to handle an
HTTP GET request containing an IPv6 address, the Squid child process
terminated due to signal 6. This bug has been fixed and such requests
are now handled as expected. (BZ#832484)

* The old 'stale if hit' logic did not account for cases where the
stored stale response became fresh due to a successful re-validation
with the origin server. Consequently, incorrect warning messages were
returned. Now, Squid no longer marks elements as stale in the
described scenario. (BZ#847056)

* When squid packages were installed before samba-winbind, the wbpriv
group did not include Squid. Consequently, NTLM authentication calls
failed. Now, Squid correctly adds itself into the wbpriv group if
samba-winbind is installed before Squid, thus fixing this bug.
(BZ#797571)

* In FIPS mode, Squid was using private MD5 hash functions for user
authentication and network access. As MD5 is incompatible with FIPS
mode, Squid could fail to start. This update limits the use of the
private MD5 functions to local disk file hash identifiers, thus
allowing Squid to work in FIPS mode. (BZ#833086)

* Under high system load, the squid process could terminate
unexpectedly with a segmentation fault during reboot. This update
provides better memory handling during reboot, thus fixing this bug.
(BZ#782732)

* Squid incorrectly set the timeout limit for client HTTP connections
with the value for server-side connections, which is much higher, thus
creating unnecessary delays. With this update, Squid uses a proper
value for the client timeout limit. (BZ#798090)

* Squid did not properly release allocated memory when generating
error page contents, which caused memory leaks. Consequently, the
Squid proxy server consumed a lot of memory within a short time
period. This update fixes this memory leak. (BZ#758861)

* Squid did not pass the ident value to a URL rewriter that was
configured using the 'url_rewrite_program' directive. Consequently,
the URL rewriter received the dash character ('-') as the user value
instead of the correct user name. Now, the URL rewriter receives the
correct user name in the described scenario. (BZ#797884)

* Squid, used as a transparent proxy, can only handle the HTTP
protocol. Previously, it was possible to define a URL in which the
access protocol contained the asterisk character (*) or an unknown
protocol namespace URI. Consequently, an 'Invalid URL' error message
was logged to access.log during reload. This update ensures that
'http://' is always used in transparent proxy URLs, and the error
message is no longer logged in this scenario. (BZ#720504)

All users of squid are advised to upgrade to these updated packages,
which fix these issues. After installing this update, the squid
service will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019514.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?575d7174"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000706.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d062cf81"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected squid package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5643");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"squid-3.1.10-16.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid");
}
