#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1660. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34500);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-3912", "CVE-2008-3913", "CVE-2008-3914");
  script_bugtraq_id(31051);
  script_xref(name:"DSA", value:"1660");

  script_name(english:"Debian DSA-1660-1 : clamav - NULL pointer dereference, resource exhaustion");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several denial-of-service vulnerabilities have been discovered in the
ClamAV anti-virus toolkit :

Insufficient checking for out-of-memory conditions results in NULL
pointer dereferences (CVE-2008-3912 ).

Incorrect error handling logic leads to memory leaks (CVE-2008-3913 )
and file descriptor leaks (CVE-2008-3914 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2008/dsa-1660"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the clamav package.

For the stable distribution (etch), these problems have been fixed in
version 0.90.1dfsg-4etch15."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/27");
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
if (deb_check(release:"4.0", prefix:"clamav", reference:"0.90.1dfsg-4etch15")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-base", reference:"0.90.1dfsg-4etch15")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-daemon", reference:"0.90.1dfsg-4etch15")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-dbg", reference:"0.90.1dfsg-4etch15")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-docs", reference:"0.90.1dfsg-4etch15")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-freshclam", reference:"0.90.1dfsg-4etch15")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-milter", reference:"0.90.1dfsg-4etch15")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-testfiles", reference:"0.90.1dfsg-4etch15")) flag++;
if (deb_check(release:"4.0", prefix:"libclamav-dev", reference:"0.90.1dfsg-4etch15")) flag++;
if (deb_check(release:"4.0", prefix:"libclamav2", reference:"0.90.1dfsg-4etch15")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
