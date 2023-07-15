#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3999. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103859);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-13082", "CVE-2017-13086", "CVE-2017-13087", "CVE-2017-13088");
  script_xref(name:"DSA", value:"3999");
  script_xref(name:"IAVA", value:"2017-A-0310");

  script_name(english:"Debian DSA-3999-1 : wpa - security update (KRACK)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mathy Vanhoef of the imec-DistriNet research group of KU Leuven
discovered multiple vulnerabilities in the WPA protocol, used for
authentication in wireless networks. Those vulnerabilities apply to
both the access point (implemented in hostapd) and the station
(implemented in wpa_supplicant).

An attacker exploiting the vulnerabilities could force the vulnerable
system to reuse cryptographic session keys, enabling a range of
cryptographic attacks against the ciphers used in WPA1 and WPA2. 

More information can be found in the researchers's paper, Key
Reinstallation Attacks: Forcing Nonce Reuse in WPA2.

  - CVE-2017-13077 :
    reinstallation of the pairwise key in the Four-way
    handshake

  - CVE-2017-13078 :
    reinstallation of the group key in the Four-way
    handshake

  - CVE-2017-13079 :
    reinstallation of the integrity group key in the
    Four-way handshake

  - CVE-2017-13080 :
    reinstallation of the group key in the Group Key
    handshake

  - CVE-2017-13081 :
    reinstallation of the integrity group key in the Group
    Key handshake

  - CVE-2017-13082 :
    accepting a retransmitted Fast BSS Transition
    Reassociation Request and reinstalling the pairwise key
    while processing it

  - CVE-2017-13086 :
    reinstallation of the Tunneled Direct-Link Setup (TDLS)
    PeerKey (TPK) key in the TDLS handshake

  - CVE-2017-13087 :
    reinstallation of the group key (GTK) when processing a
    Wireless Network Management (WNM) Sleep Mode Response
    frame

  - CVE-2017-13088 :
    reinstallation of the integrity group key (IGTK) when
    processing a Wireless Network Management (WNM) Sleep
    Mode Response frame"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.krackattacks.com/#paper"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-13077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-13078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-13079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-13080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-13081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-13082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-13086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-13087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-13088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/wpa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/wpa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3999"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wpa packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 2.3-1+deb8u5.

For the stable distribution (stretch), these problems have been fixed
in version 2:2.4-1+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"hostapd", reference:"2.3-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"wpagui", reference:"2.3-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"wpasupplicant", reference:"2.3-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"wpasupplicant-udeb", reference:"2.3-1+deb8u5")) flag++;
if (deb_check(release:"9.0", prefix:"hostapd", reference:"2:2.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wpagui", reference:"2:2.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wpasupplicant", reference:"2:2.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wpasupplicant-udeb", reference:"2:2.4-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
