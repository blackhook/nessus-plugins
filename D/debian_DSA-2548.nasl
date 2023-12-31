#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2548. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62086);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-3518", "CVE-2012-3519", "CVE-2012-4419");
  script_xref(name:"DSA", value:"2548");

  script_name(english:"Debian DSA-2548-1 : tor - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Tor, an online privacy
tool.

  - CVE-2012-3518
    Avoid an uninitialised memory read when reading a vote
    or consensus document that has an unrecognized flavour
    name. This could lead to a remote crash, resulting in
    denial of service.

  - CVE-2012-3519
    Try to leak less information about what relays a client
    is choosing to a side-channel attacker.

  - CVE-2012-4419
    By providing specially crafted date strings to a victim
    tor instance, an attacker can cause it to run into an
    assertion and shut down.

Additionally the update to stable includes the following fixes: when
waiting for a client to renegotiate, don't allow it to add any bytes
to the input buffer. This fixes a potential DoS issue [ tor-5934,
tor-6007]."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://trac.torproject.org/projects/tor/ticket/5934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://trac.torproject.org/projects/tor/ticket/6007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/tor"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2012/dsa-2548"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tor packages.

For the stable distribution (squeeze), these problems have been fixed
in version 0.2.2.39-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"tor", reference:"0.2.2.39-1")) flag++;
if (deb_check(release:"6.0", prefix:"tor-dbg", reference:"0.2.2.39-1")) flag++;
if (deb_check(release:"6.0", prefix:"tor-geoipdb", reference:"0.2.2.39-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
