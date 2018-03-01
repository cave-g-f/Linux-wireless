CFLAGS		= -g -O3 -Wall -Wextra
LINKFLAGS	= -lpthread

DESTDIR		=
PREFIX		= /usr/local
SBINDIR		= $(PREFIX)/sbin

OSD		= osdep
LIBS		= -L$(OSD) -l$(OSD)
LIBOSD		= $(OSD)/lib$(OSD).so


all: osd breakConnect

osd:
	$(MAKE) -C $(OSD)

$(LIBOSD):
	$(MAKE) -C $(OSD)

breakConnect: breakConnect.c $(OSD)/libosdep.a
	$(CC) $(CFLAGS) $(LINKFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f breakConnect
	$(MAKE) -C $(OSD) clean
