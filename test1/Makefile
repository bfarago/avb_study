
CC ?= gcc
OPT = -O2 -g
WARN=-Wall -Wextra -Wno-parentheses
CFLAGS=$(OPT) $(WARN)
#CPPFLAGS = -I$(LIB_DIR)/mylib
LDLIBS = -lpcap -pthread -lsupc++

all: test1

test1: test1.o ethif.o avdecc.o sockif.o sockpcap.o timercounter.o

%: %.o
		$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

clean:
		$(RM)  test1
		$(RM) `find . -name "*~" -o -name "*.[oa]" -o -name "\#*\#" -o -name TAGS -o -name core -o -name "*.orig"`

