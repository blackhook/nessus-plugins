#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2989. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76844);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-0118", "CVE-2014-0226", "CVE-2014-0231");
  script_bugtraq_id(68678, 68742, 68745);
  script_xref(name:"DSA", value:"2989");

  script_name(english:"Debian DSA-2989-1 : apache2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security issues were found in the Apache HTTP server.

  - CVE-2014-0118
    The DEFLATE input filter (inflates request bodies) in
    mod_deflate allows remote attackers to cause a denial of
    service (resource consumption) via crafted request data
    that decompresses to a much larger size.

  - CVE-2014-0226
    A race condition was found in mod_status. An attacker
    able to access a public server status page on a server
    could send carefully crafted requests which could lead
    to a heap buffer overflow, causing denial of service,
    disclosure of sensitive information, or potentially the
    execution of arbitrary code.

  - CVE-2014-0231
    A flaw was found in mod_cgid. If a server using mod_cgid
    hosted CGI scripts which did not consume standard input,
    a remote attacker could cause child processes to hang
    indefinitely, leading to denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/apache2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2014/dsa-2989"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apache2 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 2.2.22-13+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"apache2", reference:"2.2.22-13+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-dbg", reference:"2.2.22-13+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-doc", reference:"2.2.22-13+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-mpm-event", reference:"2.2.22-13+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-mpm-itk", reference:"2.2.22-13+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-mpm-prefork", reference:"2.2.22-13+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-mpm-worker", reference:"2.2.22-13+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-prefork-dev", reference:"2.2.22-13+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-suexec", reference:"2.2.22-13+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-suexec-custom", reference:"2.2.22-13+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-threaded-dev", reference:"2.2.22-13+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-utils", reference:"2.2.22-13+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"apache2.2-bin", reference:"2.2.22-13+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"apache2.2-common", reference:"2.2.22-13+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
