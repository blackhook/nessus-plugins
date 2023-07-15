#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2021-4.0-0102. The text
# itself is copyright (C) VMware, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153494);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/12");

  script_cve_id("CVE-2021-22945", "CVE-2021-22946", "CVE-2021-22947");

  script_name(english:"Photon OS 4.0: Curl PHSA-2021-4.0-0102");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the curl package has been released.

  - When sending data to an MQTT server, libcurl <= 7.73.0 and 7.78.0 could in some circumstances erroneously
    keep a pointer to an already freed memory area and both use that again in a subsequent call to send data
    and also free it *again*. (CVE-2021-22945)

  - A user can tell curl >= 7.20.0 and <= 7.78.0 to require a successful upgrade to TLS when speaking to an
    IMAP, POP3 or FTP server (`--ssl-reqd` on the command line or`CURLOPT_USE_SSL` set to `CURLUSESSL_CONTROL`
    or `CURLUSESSL_ALL` withlibcurl). This requirement could be bypassed if the server would return a properly
    crafted but perfectly legitimate response.This flaw would then make curl silently continue its operations
    **withoutTLS** contrary to the instructions and expectations, exposing possibly sensitive data in clear
    text over the network. (CVE-2021-22946)

  - When curl >= 7.20.0 and <= 7.78.0 connects to an IMAP or POP3 server to retrieve data using STARTTLS to
    upgrade to TLS security, the server can respond and send back multiple responses at once that curl caches.
    curl would then upgrade to TLS but not flush the in-queue of cached responses but instead continue using
    and trustingthe responses it got *before* the TLS handshake as if they were authenticated.Using this flaw,
    it allows a Man-In-The-Middle attacker to first inject the fake responses, then pass-through the TLS
    traffic from the legitimate server and trick curl into sending data back to the user thinking the
    attacker's injected data comes from the TLS-protected server. (CVE-2021-22947)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-4.0-102.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22945");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:4.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/PhotonOS/release');
if (isnull(release) || release !~ "^VMware Photon") audit(AUDIT_OS_NOT, 'PhotonOS');
if (release !~ "^VMware Photon (?:Linux|OS) 4\.0(\D|$)") audit(AUDIT_OS_NOT, 'PhotonOS 4.0');

if (!get_kb_item('Host/PhotonOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'PhotonOS', cpu);

var flag = 0;

if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'curl-7.78.0-2.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'curl-devel-7.78.0-2.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'curl-libs-7.78.0-2.ph4')) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl');
}
