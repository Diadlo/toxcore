lib_LTLIBRARIES += libtoxplatform.la

libtoxplatform_la_include_HEADERS = \
                                    ../toxplatform/network.h

libtoxplatform_la_includedir = $(includedir)/tox

libtoxplatform_la_SOURCES = \
                            ../toxplatform/network.h \
                            ../toxplatform/network.c 

libtoxplatform_la_CFLAGS = \
                           -I$(top_srcdir)

libtoxplatform_la_LDFLAGS = \
                            $(EXTRA_LT_LDFLAGS) \
                            $(RT_LIBS) \
                            $(WINSOCK2_LIBS)
