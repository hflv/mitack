DIR=		server
TOP=		..
CC=	gcc
INCLUDES= -I ./ -I /usr/inlcude/ 
CFLAGS= -Wl,-rpath,../ -fPIC $(INCLUDES)
#CFLAGS= -fPIC $(INCLUDES)
DLIBCRYPTO=-L.. -lcrypto
DLIBSSL=-L.. -lssl
DLIBDL=-ldl


E_SRC_S=	ssl2server.c apps_lhf.c \
s_cb_lhf.c s_socket_lhf.c

E_OBJ_S=	ssl2server.o apps_lhf.o \
s_cb_lhf.o s_socket_lhf.o

E_PRG_S = ssl2server

#all target  
 
#%.o: %.c
#	$(CC) $(CFLAGS) -c $(E_SRC_S)
	
	
#$(E_PRG_S):$(E_OBJ_S)
#	$(CC) $(CFLAGS) $(E_OBJ_S) -o $@ $(DLIBCRYPTO) $(DLIBSSL) $(DLIBDL) 
	
all:$(E_PRG_S)
$(E_PRG_S):
	$(CC) $(CFLAGS) -o $(E_PRG_S) $(E_SRC_S) $(DLIBCRYPTO) $(DLIBSSL) $(DLIBDL) 

.PHONY:clean
clean:    
	rm -f $(E_PRG_S)