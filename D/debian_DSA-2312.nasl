#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2312. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56339);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2011-2372", "CVE-2011-2995", "CVE-2011-2998", "CVE-2011-2999", "CVE-2011-3000");
  script_bugtraq_id(49809, 49810, 49811, 49848, 49849);
  script_xref(name:"DSA", value:"2312");

  script_name(english:"Debian DSA-2312-1 : iceape - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in the Iceape internet suite,
an unbranded version of SeaMonkey :

  - CVE-2011-2372
    Mariusz Mlynski discovered that websites could open a
    download dialog -- which has 'open' as the default
    action --, while a user presses the ENTER key.

  - CVE-2011-2995
    Benjamin Smedberg, Bob Clary and Jesse Ruderman
    discovered crashes in the rendering engine, which could
    lead to the execution of arbitrary code.

  - CVE-2011-2998
    Mark Kaplan discovered an integer underflow in the
    JavaScript engine, which could lead to the execution of
    arbitrary code.

  - CVE-2011-2999
    Boris Zbarsky discovered that incorrect handling of the
    window.location object could lead to bypasses of the
    same-origin policy.

  - CVE-2011-3000
    Ian Graham discovered that multiple Location headers
    might lead to CRLF injection.

The oldstable distribution (lenny) is not affected. The iceape package
only provides the XPCOM code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/iceape"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2011/dsa-2312"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceape packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.0.11-8. This update also marks the compromised DigiNotar
root certs as revoked rather then untrusted."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceape");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"iceape", reference:"2.0.11-8")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-browser", reference:"2.0.11-8")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-chatzilla", reference:"2.0.11-8")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-dbg", reference:"2.0.11-8")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-dev", reference:"2.0.11-8")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-mailnews", reference:"2.0.11-8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
