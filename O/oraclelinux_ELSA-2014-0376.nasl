#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:0376 and 
# Oracle Linux Security Advisory ELSA-2014-0376 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73395);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-0160");
  script_xref(name:"RHSA", value:"2014:0376");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"Oracle Linux 6 : openssl (ELSA-2014-0376)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"From Red Hat Security Advisory 2014:0376 :

Updated openssl packages that fix one security issue are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

An information disclosure flaw was found in the way OpenSSL handled
TLS and DTLS Heartbeat Extension packets. A malicious TLS or DTLS
client or server could send a specially crafted TLS or DTLS Heartbeat
packet to disclose a limited portion of memory per request from a
connected client or server. Note that the disclosed portions of memory
could potentially include sensitive information such as private keys.
(CVE-2014-0160)

Red Hat would like to thank the OpenSSL project for reporting this
issue. Upstream acknowledges Neel Mehta of Google Security as the
original reporter.

All OpenSSL users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. For the update
to take effect, all services linked to the OpenSSL library (such as
httpd and other SSL-enabled services) must be restarted or the system
rebooted.");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2014-April/004065.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0160");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'OpenSSL Heartbeat Information Leak');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);


flag = 0;
if (rpm_check(release:"EL6", reference:"openssl-1.0.1e-16.el6_5.7")) flag++;
if (rpm_check(release:"EL6", reference:"openssl-devel-1.0.1e-16.el6_5.7")) flag++;
if (rpm_check(release:"EL6", reference:"openssl-perl-1.0.1e-16.el6_5.7")) flag++;
if (rpm_check(release:"EL6", reference:"openssl-static-1.0.1e-16.el6_5.7")) flag++;


if (flag)
{
  report = rpm_report_get();

  if(!egrep(pattern:"package installed.+openssl[^0-9]*\-1\.0\.1", string:report)) exit(0, "The remote host does not use OpenSSL 1.0.1");

  if (report_verbosity > 0) security_warning(port:0, extra:report);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
