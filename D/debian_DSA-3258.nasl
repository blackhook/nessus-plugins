#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3258. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83381);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-3427");
  script_bugtraq_id(74339);
  script_xref(name:"DSA", value:"3258");

  script_name(english:"Debian DSA-3258-1 : quassel - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the fix for CVE-2013-4422 in quassel, a
distributed IRC client, was incomplete. This could allow remote
attackers to inject SQL queries after a database reconnection (e.g.
when the backend PostgreSQL server is restarted)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=783926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/quassel"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2015/dsa-3258"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the quassel packages.

For the stable distribution (jessie), this problem has been fixed in
version 1:0.10.0-2.3+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:quassel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"quassel", reference:"1:0.10.0-2.3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"quassel-client", reference:"1:0.10.0-2.3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"quassel-client-kde4", reference:"1:0.10.0-2.3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"quassel-core", reference:"1:0.10.0-2.3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"quassel-data", reference:"1:0.10.0-2.3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"quassel-data-kde4", reference:"1:0.10.0-2.3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"quassel-kde4", reference:"1:0.10.0-2.3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
