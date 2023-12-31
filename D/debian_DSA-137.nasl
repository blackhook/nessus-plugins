#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-137. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14974);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2002-0658");
  script_bugtraq_id(5352);
  script_xref(name:"DSA", value:"137");

  script_name(english:"Debian DSA-137-1 : mm - insecure temporary files");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Marcus Meissner and Sebastian Krahmer discovered and fixed a temporary
file vulnerability in the mm shared memory library. This problem can
be exploited to gain root access to a machine running Apache which is
linked against this library, if shell access to the user 'www-data' is
already available (which could easily be triggered through PHP)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-137"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libmm packages immediately and restart the Apache server.

This problem has been fixed in the upstream version 1.2.0 of mm, which
will be uploaded to the unstable Debian distribution while this
advisory is released. Fixed packages for potato (Debian 2.2) and woody
(Debian 3.0) are linked below."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"libmm10", reference:"1.0.11-1.2")) flag++;
if (deb_check(release:"2.2", prefix:"libmm10-dev", reference:"1.0.11-1.2")) flag++;
if (deb_check(release:"3.0", prefix:"libmm11", reference:"1.1.3-6.1")) flag++;
if (deb_check(release:"3.0", prefix:"libmm11-dev", reference:"1.1.3-6.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
