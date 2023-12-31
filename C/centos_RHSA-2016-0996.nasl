#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0996 and 
# CentOS Errata and Security Advisory 2016:0996 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91171);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-0799", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2108", "CVE-2016-2109", "CVE-2016-2842");
  script_xref(name:"RHSA", value:"2016:0996");

  script_name(english:"CentOS 6 : openssl (CESA-2016:0996)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for openssl is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL)
and Transport Layer Security (TLS) protocols, as well as a
full-strength general-purpose cryptography library.

Security Fix(es) :

* A flaw was found in the way OpenSSL encoded certain ASN.1 data
structures. An attacker could use this flaw to create a specially
crafted certificate which, when verified or re-encoded by OpenSSL,
could cause it to crash, or execute arbitrary code using the
permissions of the user running an application compiled against the
OpenSSL library. (CVE-2016-2108)

* Two integer overflow flaws, leading to buffer overflows, were found
in the way the EVP_EncodeUpdate() and EVP_EncryptUpdate() functions of
OpenSSL parsed very large amounts of input data. A remote attacker
could use these flaws to crash an application using OpenSSL or,
possibly, execute arbitrary code with the permissions of the user
running that application. (CVE-2016-2105, CVE-2016-2106)

* It was discovered that OpenSSL leaked timing information when
decrypting TLS/SSL and DTLS protocol encrypted records when the
connection used the AES CBC cipher suite and the server supported
AES-NI. A remote attacker could possibly use this flaw to retrieve
plain text from encrypted packets by using a TLS/SSL or DTLS server as
a padding oracle. (CVE-2016-2107)

* Several flaws were found in the way BIO_*printf functions were
implemented in OpenSSL. Applications which passed large amounts of
untrusted data through these functions could crash or potentially
execute code with the permissions of the user running such an
application. (CVE-2016-0799, CVE-2016-2842)

* A denial of service flaw was found in the way OpenSSL parsed certain
ASN.1-encoded data from BIO (OpenSSL's I/O abstraction) inputs. An
application using OpenSSL that accepts untrusted ASN.1 BIO input could
be forced to allocate an excessive amount of data. (CVE-2016-2109)

Red Hat would like to thank the OpenSSL project for reporting
CVE-2016-2108, CVE-2016-2842, CVE-2016-2105, CVE-2016-2106,
CVE-2016-2107, and CVE-2016-0799. Upstream acknowledges Huzaifa
Sidhpurwala (Red Hat), Hanno Böck, and David Benjamin (Google) as the
original reporters of CVE-2016-2108; Guido Vranken as the original
reporter of CVE-2016-2842, CVE-2016-2105, CVE-2016-2106, and
CVE-2016-0799; and Juraj Somorovsky as the original reporter of
CVE-2016-2107."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-May/003097.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b86a0c1f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}

# Temporarily disabled
exit(0);

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"openssl-1.0.1e-48.el6_8.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-devel-1.0.1e-48.el6_8.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-perl-1.0.1e-48.el6_8.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-static-1.0.1e-48.el6_8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
