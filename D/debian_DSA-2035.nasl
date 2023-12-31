#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2035. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45557);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-0408", "CVE-2010-0434");
  script_bugtraq_id(38491, 38580);
  script_xref(name:"DSA", value:"2035");

  script_name(english:"Debian DSA-2035-1 : apache2 - multiple issues");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two issues have been found in the Apache HTTPD web server :

  - CVE-2010-0408
    mod_proxy_ajp would return the wrong status code if it
    encountered an error, causing a backend server to be put
    into an error state until the retry timeout expired. A
    remote attacker could send malicious requests to trigger
    this issue, resulting in denial of service.

  - CVE-2010-0434
    A flaw in the core subrequest process code was found,
    which could lead to a daemon crash (segfault) or
    disclosure of sensitive information if the headers of a
    subrequest were modified by modules such as mod_headers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2010/dsa-2035"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apache2 and apache2-mpm-itk packages.

For the stable distribution (lenny), these problems have been fixed in
version 2.2.9-10+lenny7.

This advisory also provides updated apache2-mpm-itk packages which
have been recompiled against the new apache2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"5.0", prefix:"apache2", reference:"2.2.9-10+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-dbg", reference:"2.2.9-10+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-doc", reference:"2.2.9-10+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-mpm-event", reference:"2.2.9-10+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-mpm-itk", reference:"2.2.6-02-1+lenny2+b3")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-mpm-prefork", reference:"2.2.9-10+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-mpm-worker", reference:"2.2.9-10+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-prefork-dev", reference:"2.2.9-10+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-src", reference:"2.2.9-10+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-suexec", reference:"2.2.9-10+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-suexec-custom", reference:"2.2.9-10+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-threaded-dev", reference:"2.2.9-10+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-utils", reference:"2.2.9-10+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"apache2.2-common", reference:"2.2.9-10+lenny7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
