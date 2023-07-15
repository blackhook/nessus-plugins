#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1090 and 
# CentOS Errata and Security Advisory 2015:1090 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84198);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-1863", "CVE-2015-4142");
  script_bugtraq_id(74296, 74549);
  script_xref(name:"RHSA", value:"2015:1090");

  script_name(english:"CentOS 7 : wpa_supplicant (CESA-2015:1090)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated wpa_supplicant package that fixes two security issues and
adds one enhancement is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The wpa_supplicant package contains an 802.1X Supplicant with support
for WEP, WPA, WPA2 (IEEE 802.11i / RSN), and various EAP
authentication methods. It implements key negotiation with a WPA
Authenticator for client stations and controls the roaming and IEEE
802.11 authentication and association of the WLAN driver.

A buffer overflow flaw was found in the way wpa_supplicant handled
SSID information in the Wi-Fi Direct / P2P management frames. A
specially crafted frame could allow an attacker within Wi-Fi radio
range to cause wpa_supplicant to crash or, possibly, execute arbitrary
code. (CVE-2015-1863)

An integer underflow flaw, leading to a buffer over-read, was found in
the way wpa_supplicant handled WMM Action frames. A specially crafted
frame could possibly allow an attacker within Wi-Fi radio range to
cause wpa_supplicant to crash. (CVE-2015-4142)

Red Hat would like to thank Jouni Malinen of the wpa_supplicant
upstream for reporting the CVE-2015-1863 issue. Upstream acknowledges
Alibaba security team as the original reporter.

This update also adds the following enhancement :

* Prior to this update, wpa_supplicant did not provide a way to
require the host name to be listed in an X.509 certificate's Common
Name or Subject Alternative Name, and only allowed host name suffix or
subject substring checks. This update introduces a new configuration
directive, 'domain_match', which adds a full host name check.
(BZ#1178263)

All wpa_supplicant users are advised to upgrade to this updated
package, which contains backported patches to correct these issues and
add this enhancement. After installing this update, the wpa_supplicant
service will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-June/021171.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8aa30a5a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wpa_supplicant package."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1863");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wpa_supplicant");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/16");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"wpa_supplicant-2.0-17.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wpa_supplicant");
}
