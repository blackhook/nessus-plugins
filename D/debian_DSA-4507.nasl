#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4507. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128125);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/02");

  script_cve_id("CVE-2019-12525", "CVE-2019-12527", "CVE-2019-12529", "CVE-2019-12854", "CVE-2019-13345");
  script_xref(name:"DSA", value:"4507");

  script_name(english:"Debian DSA-4507-1 : squid - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Squid, a fully featured web
proxy cache. The flaws in the HTTP Digest Authentication processing,
the HTTP Basic Authentication processing and in the cachemgr.cgi
allowed remote attackers to perform denial of service and cross-site
scripting attacks, and potentially the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=931478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/squid"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/squid"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4507"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the squid packages.

For the stable distribution (buster), these problems have been fixed
in version 4.6-1+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"squid", reference:"4.6-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"squid-cgi", reference:"4.6-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"squid-common", reference:"4.6-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"squid-purge", reference:"4.6-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"squid3", reference:"4.6-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"squidclient", reference:"4.6-1+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
