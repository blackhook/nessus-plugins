#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1652. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34388);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905");
  script_bugtraq_id(30644, 30802, 31699);
  script_xref(name:"DSA", value:"1652");

  script_name(english:"Debian DSA-1652-1 : ruby1.9 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the interpreter for
the Ruby language, which may lead to denial of service and other
security problems. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2008-3655
    Keita Yamaguchi discovered that several safe level
    restrictions are insufficiently enforced.

  - CVE-2008-3656
    Christian Neukirchen discovered that the WebRick module
    uses inefficient algorithms for HTTP header splitting,
    resulting in denial of service through resource
    exhaustion.

  - CVE-2008-3657
    It was discovered that the dl module doesn't perform
    taintness checks.

  - CVE-2008-3790
    Luka Treiber and Mitja Kolsek discovered that
    recursively nested XML entities can lead to denial of
    service through resource exhaustion in rexml.

  - CVE-2008-3905
    Tanaka Akira discovered that the resolv module uses
    sequential transaction IDs and a fixed source port for
    DNS queries, which makes it more vulnerable to DNS
    spoofing attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2008/dsa-1652"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ruby1.9 packages.

For the stable distribution (etch), these problems have been fixed in
version 1.9.0+20060609-1etch3. Packages for arm will be provided
later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"4.0", prefix:"irb1.9", reference:"1.9.0+20060609-1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libdbm-ruby1.9", reference:"1.9.0+20060609-1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libgdbm-ruby1.9", reference:"1.9.0+20060609-1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libopenssl-ruby1.9", reference:"1.9.0+20060609-1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libreadline-ruby1.9", reference:"1.9.0+20060609-1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libruby1.9", reference:"1.9.0+20060609-1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libruby1.9-dbg", reference:"1.9.0+20060609-1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libtcltk-ruby1.9", reference:"1.9.0+20060609-1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"rdoc1.9", reference:"1.9.0+20060609-1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ri1.9", reference:"1.9.0+20060609-1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.9", reference:"1.9.0+20060609-1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.9-dev", reference:"1.9.0+20060609-1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.9-elisp", reference:"1.9.0+20060609-1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.9-examples", reference:"1.9.0+20060609-1etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
