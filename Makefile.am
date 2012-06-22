# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
#     Mischa Sall\'e <msalle@nikhef.nl>
#

AM_CPPFLAGS = -DPAM_MYPROXY_CONF=\"@CONFIG_FILE@\"
AM_CFLAGS = \
    -Wall \
    -Wuninitialized -Wbad-function-cast -Wcast-align -Wcast-qual \
    -Wmissing-prototypes -Wpointer-arith -Wredundant-decls \
    -Wshadow -Wstrict-prototypes -Wpointer-arith -Wno-long-long -Wundef

EXTRA_DIST = LICENSE \
	     bootstrap

# Library
securelibdir = @SECUREDIR@

securelib_LTLIBRARIES = pam_myproxy.la
pam_myproxy_la_LDFLAGS = -module -avoid-version
pam_myproxy_la_SOURCES = \
    pam_myproxy.h pam_myproxy_opts.c \
    myproxy_client.c myproxy_client.h \
    pam_myproxy.c

# Test program
sbin_PROGRAMS = myproxy_test_client
myproxy_test_client_CFLAGS = -DMAKE_A_OUT
myproxy_test_client_SOURCES = \
    pam_myproxy.h pam_myproxy_opts.c \
    myproxy_client.c myproxy_client.h \
    testclient.c
