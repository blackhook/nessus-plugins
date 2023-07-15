#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1150-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104299);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-13082", "CVE-2017-13086", "CVE-2017-13087", "CVE-2017-13088");
  script_xref(name:"IAVA", value:"2017-A-0310");

  script_name(english:"Debian DLA-1150-1 : wpa security update (KRACK)");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability was found in how WPA code can be triggered to
reconfigure WPA/WPA2/RSN keys (TK, GTK, or IGTK) by replaying a
specific frame that is used to manage the keys. Such reinstallation of
the encryption key can result in two different types of
vulnerabilities: disabling replay protection and significantly
reducing the security of encryption to the point of allowing frames to
be decrypted or some parts of the keys to be determined by an attacker
depending on which cipher is used.

Those issues are commonly known under the 'KRACK' appelation.
According to US-CERT, 'the impact of exploiting these vulnerabilities
includes decryption, packet replay, TCP connection hijacking, HTTP
content injection, and others.'

CVE-2017-13077

Reinstallation of the pairwise encryption key (PTK-TK) in the 4-way
handshake.

CVE-2017-13078

Reinstallation of the group key (GTK) in the 4-way handshake.

CVE-2017-13079

Reinstallation of the integrity group key (IGTK) in the 4-way
handshake.

CVE-2017-13080

Reinstallation of the group key (GTK) in the group key handshake.

CVE-2017-13081

Reinstallation of the integrity group key (IGTK) in the group key
handshake.

CVE-2017-13082

Accepting a retransmitted Fast BSS Transition (FT) Reassociation
Request and reinstalling the pairwise encryption key (PTK-TK) while
processing it.

CVE-2017-13084

Reinstallation of the STK key in the PeerKey handshake.

CVE-2017-13086

reinstallation of the Tunneled Direct-Link Setup (TDLS) PeerKey (TPK)
key in the TDLS handshake.

CVE-2017-13087

reinstallation of the group key (GTK) when processing a Wireless
Network Management (WNM) Sleep Mode Response frame.

CVE-2017-13088

reinstallation of the integrity group key (IGTK) when processing a
Wireless Network Management (WNM) Sleep Mode Response frame.

For Debian 7 'Wheezy', these problems have been fixed in version
1.0-3+deb7u5. Note that the latter two vulnerabilities (CVE-2017-13087
and CVE-2017-13088) were mistakenly marked as fixed in the changelog
whereas they simply did not apply to the 1.0 version of the WPA source
code, which doesn't implement WNM sleep mode responses.

We recommend that you upgrade your wpa packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/10/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/wpa"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hostapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpagui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpasupplicant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpasupplicant-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"hostapd", reference:"1.0-3+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"wpagui", reference:"1.0-3+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"wpasupplicant", reference:"1.0-3+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"wpasupplicant-udeb", reference:"1.0-3+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
