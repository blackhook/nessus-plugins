#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2020 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include("compat.inc");

if (description)
{
  script_id(139715);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/21");

  script_cve_id("CVE-2020-8231");
  script_xref(name:"IAVA", value:"2020-A-0389-S");

  script_name(english:"FreeBSD : curl -- expired pointer dereference vulnerability (b905dff4-e227-11ea-b0ea-08002728f74c)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"curl security problems :

CVE-2020-8231: wrong connect-only connection

An application that performs multiple requests with libcurl's multi
API and sets the CURLOPT_CONNECT_ONLY option, might in rare
circumstances experience that when subsequently using the setup
connect-only transfer, libcurl will pick and use the wrong connection
- and instead pick another one the application has created since then.

CURLOPT_CONNECT_ONLY is the option to tell libcurl to not perform an
actual transfer, only connect. When that operation is completed,
libcurl remembers which connection it used for that transfer and 'easy
handle'. It remembers the connection using a pointer to the internal
connectdata struct in memory.

If more transfers are then done with the same multi handle before the
connect-only connection is used, leading to the initial connect-only
connection to get closed (for example due to idle time-out) while also
new transfers (and connections) are setup, such a new connection might
end up getting the exact same memory address as the now closed
connect-only connection.

If after those operations, the application then wants to use the
original transfer's connect-only setup to for example use
curl_easy_send() to send raw data over that connection, libcurl could
erroneously find an existing connection still being alive at the
address it remembered since before even though this is now a new and
different connection.

The application could then accidentally send data over that connection
which wasn't at all intended for that recipient, entirely unknowingly."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/security.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/CVE-2020-8231.html"
  );
  # https://vuxml.freebsd.org/freebsd/b905dff4-e227-11ea-b0ea-08002728f74c.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20a6717e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8231");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"curl>=7.29.0<7.72.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
