#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2019 Jacques Vidrine and contributors
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
  script_id(128795);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/27");

  script_cve_id("CVE-2019-5481", "CVE-2019-5482");

  script_name(english:"FreeBSD : curl -- multiple vulnerabilities (9fb4e57b-d65a-11e9-8a5f-e5c82b486287)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"curl security problems :

CVE-2019-5481: FTP-KRB double-free

libcurl can be told to use kerberos over FTP to a server, as set with
the CURLOPT_KRBLEVEL option.

During such kerberos FTP data transfer, the server sends data to curl
in blocks with the 32 bit size of each block first and then that
amount of data immediately following.

A malicious or just broken server can claim to send a very large block
and if by doing that it makes curl's subsequent call to realloc() to
fail, curl would then misbehave in the exit path and double-free the
memory.

In practical terms, an up to 4 GB memory area may very well be fine to
allocate on a modern 64 bit system but on 32 bit systems it will fail.

Kerberos FTP is a rarely used protocol with curl. Also, Kerberos
authentication is usually only attempted and used with servers that
the client has a previous association with.

CVE-2019-5482: TFTP small blocksize heap buffer overflow

libcurl contains a heap buffer overflow in the function
(tftp_receive_packet()) that receives data from a TFTP server. It can
call recvfrom() with the default size for the buffer rather than with
the size that was used to allocate it. Thus, the content that might
overwrite the heap memory is controlled by the server.

This flaw is only triggered if the TFTP server sends an OACK without
the BLKSIZE option, when a BLKSIZE smaller than 512 bytes was
requested by the TFTP client. OACK is a TFTP extension and is not used
by all TFTP servers.

Users choosing a smaller block size than default should be rare as the
primary use case for changing the size is to make it larger.

It is rare for users to use TFTP across the Internet. It is most
commonly used within local networks. TFTP as a protocol is always
inherently insecure.

This issue was introduced by the add of the TFTP BLKSIZE option
handling. It was previously incompletely fixed by an almost identical
issue called CVE-2019-5436."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/security.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/CVE-2019-5481.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/CVE-2019-5482.html"
  );
  # https://vuxml.freebsd.org/freebsd/9fb4e57b-d65a-11e9-8a5f-e5c82b486287.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0784ba7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"curl>=7.19.4<7.66.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
