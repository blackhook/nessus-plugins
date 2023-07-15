#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1439 and 
# CentOS Errata and Security Advisory 2015:1439 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85021);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-4142");
  script_bugtraq_id(74549);
  script_xref(name:"RHSA", value:"2015:1439");

  script_name(english:"CentOS 6 : wpa_supplicant (CESA-2015:1439)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated wpa_supplicant package that fixes one security issue and
adds one enhancement is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

The wpa_supplicant package contains an 802.1X Supplicant with support
for WEP, WPA, WPA2 (IEEE 802.11i / RSN), and various EAP
authentication methods. It implements key negotiation with a WPA
Authenticator for client stations and controls the roaming and IEEE
802.11 authentication and association of the WLAN driver.

An integer underflow flaw, leading to a buffer over-read, was found in
the way wpa_supplicant handled WMM Action frames. A specially crafted
frame could possibly allow an attacker within Wi-Fi radio range to
cause wpa_supplicant to crash. (CVE-2015-4142)

This update includes the following enhancement :

* Prior to this update, wpa_supplicant did not provide a way to
require the host name to be listed in an X.509 certificate's Common
Name or Subject Alternative Name, and only allowed host name suffix or
subject substring checks. This update introduces a new configuration
directive, 'domain_match', which adds a full host name check.
(BZ#1186806)

All wpa_supplicant users are advised to upgrade to this updated
package, which contains a backported patch to correct this issue and
adds this enhancement. After installing this update, the
wpa_supplicant service will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-July/002064.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9f2b7b3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wpa_supplicant package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4142");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wpa_supplicant");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/15");
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
if (rpm_check(release:"CentOS-6", reference:"wpa_supplicant-0.7.3-6.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wpa_supplicant");
}
