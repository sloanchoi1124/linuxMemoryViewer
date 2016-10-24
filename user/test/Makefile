TARGET=test
SOURCES=test.c

# You probably don't need to change below

OBJECTS=$(SOURCES:%.c=%.o)

BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
OBJDIR=../../build-$(BRANCH)/$(shell basename $(CURDIR))
SYSROOT=--sysroot=../sysroot

CC=aarch64-linux-android-gcc

INCLUDE=

LDLIBS=-L../sysroot/lib64

CFLAGS=-Wall  -g -pie  -fdata-sections -ffunction-sections $(SYSROOT) $(INCLUDE)
LDFLAGS=$(SYSROOT) -pie

TARGET:=$(addprefix $(OBJDIR)/,$(TARGET))
OBJECTS:=$(addprefix $(OBJDIR)/,$(OBJECTS))

.PHONY: default clean

default: $(OBJDIR) $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -rf $(OBJDIR)
