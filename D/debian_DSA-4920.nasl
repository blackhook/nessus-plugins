#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4920. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149897);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/14");

  script_cve_id("CVE-2021-31535");
  script_xref(name:"DSA", value:"4920");

  script_name(english:"Debian DSA-4920-1 : libx11 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Roman Fiedler reported that missing length validation in various
functions provided by libx11, the X11 client-side library, allow to
inject X11 protocol commands on X clients, leading to authentication
bypass, denial of service or potentially the execution of arbitrary
code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=988737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/libx11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/libx11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4920"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the libx11 packages.

For the stable distribution (buster), this problem has been fixed in
version 2:1.6.7-1+deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31535");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"libx11-6", reference:"2:1.6.7-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libx11-6-udeb", reference:"2:1.6.7-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libx11-data", reference:"2:1.6.7-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libx11-dev", reference:"2:1.6.7-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libx11-doc", reference:"2:1.6.7-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libx11-xcb-dev", reference:"2:1.6.7-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libx11-xcb1", reference:"2:1.6.7-1+deb10u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
